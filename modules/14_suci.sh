#!/usr/bin/env bash
# SUCI Deconcealment — concealment, deconcealment and the attack surface
#
# This module does real cryptography, not a sketch of it:
#
#   TS 33.501 Annex C   the SUCI concealment scheme (ECIES, profiles A and B)
#   TS 23.003 §2.2      the SUCI structure and its field offsets
#   TS 23.003 §2.2      the MSIN BCD encoding (nibble-swapped, 0xF filler)
#   RFC 5869            HKDF-SHA256, implemented explicitly (extract, expand)
#   RFC 7748            X25519 for profile A
#   SEC 1 §4.3.6        P-256 point compression for profile B (SEC1/SEC2)
#   NIST SP 800-38A     AES-128-CTR for the MSIN encryption
#
# Profile A: ECIES with X25519. Profile B: the same construction with
# secp256r1 (P-256) and a compressed ephemeral public key. Both derive the
# encryption key with HKDF-SHA256 and encrypt the BCD-encoded MSIN with
# AES-128-CTR under the initial counter block 0^127 || 1.
#
# python3 plus the `cryptography` package is used for the elliptic-curve and
# AES primitives. If that package is missing, HKDF and the BCD codec still
# run (they are pure hashlib/hmac) and the profile A/B operations SKIP with
# the missing package named — they never fail silently or fake a result.
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

SUCI_CAPABLE=1
# Guarded: when the launcher sources every module into one shell, an
# unconditional definition here would clobber the launcher's own banner.
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

MOD_TMP="$TMP_DIR/suci"
SUCI_DIR="$LOOT_DIR/suci"
SUCI_KEYDIR="$SUCI_DIR/keys"
mkdir -p "$MOD_TMP" "$SUCI_DIR" "$SUCI_KEYDIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
suci_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── python capability detection ─────────────────────────────────────────
# The package is named explicitly wherever it is missing, because "crypto
# unavailable" is not an answer a researcher can act on.
suci_have_python() {
    command -v python3 >/dev/null 2>&1
}

suci_have_cryptography() {
    suci_have_python || return 1
    python3 -c 'import cryptography' >/dev/null 2>&1
}

suci_missing_dep() {
    if ! suci_have_python; then
        echo "python3"
    elif ! suci_have_cryptography; then
        echo "python3 'cryptography' package"
    fi
}

# ── BCD MSIN codec (TS 23.003 §2.2) ─────────────────────────────────────
# The MSIN is stored as BCD with the digits swapped in pairs: the first digit
# goes in the low nibble of the first octet, the second in the high nibble,
# and so on. An odd number of digits is padded with 0xF in the final high
# nibble, and that filler must be dropped on decode — otherwise a 9-digit
# MSIN comes back as 10 digits ending in "f".
suci_msin_encode() {
    local msin="${1:-}"
    [[ "$msin" =~ ^[0-9]{1,20}$ ]] || {
        printf 'ERROR\tMSIN must be 1..20 decimal digits: %s\n' "$(suci_sanitize "$msin")" >&2
        return 2
    }
    local i n=${#msin} out=""
    for (( i = 0; i < n; i += 2 )); do
        local lo="${msin:i:1}"
        local hi="f"
        (( i + 1 < n )) && hi="${msin:i+1:1}"
        out+="${hi}${lo}"
    done
    printf '%s' "$out"
}

suci_msin_decode() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    hex="${hex,,}"
    [[ "$hex" =~ ^[0-9a-f]+$ ]] || {
        printf 'ERROR\tBCD MSIN must be hex\n' >&2; return 2
    }
    (( ${#hex} % 2 == 0 && ${#hex} >= 2 )) || {
        printf 'ERROR\tBCD MSIN must be a whole number of octets\n' >&2; return 2
    }
    # Octet layout, matching suci_msin_encode: the FIRST character of each
    # octet pair is the high nibble and holds the second digit (or the 0xF
    # filler when the digit count is odd); the SECOND character is the low
    # nibble and holds the first digit. So the digit order is
    #   char[1], char[0], char[3], char[2], ...
    local i out=""
    local n_octets=$(( ${#hex} / 2 ))
    for (( i = 0; i < ${#hex}; i += 2 )); do
        local hi="${hex:i:1}" lo="${hex:i+1:1}"
        local last=$(( i / 2 == n_octets - 1 ))
        if [[ ! "$lo" =~ [0-9] ]]; then
            printf 'ERROR\tBCD low nibble "%s" is not a decimal digit\n' "$lo" >&2
            return 1
        fi
        out+="$lo"
        if [[ "$hi" == "f" ]]; then
            # 0xF is the odd-digit filler, legal only in the final octet.
            if (( ! last )); then
                printf 'ERROR\tBCD filler 0xF in a non-final octet\n' >&2
                return 1
            fi
        elif [[ "$hi" =~ [0-9] ]]; then
            out+="$hi"
        else
            printf 'ERROR\tBCD high nibble "%s" is not a decimal digit or the 0xF filler\n' "$hi" >&2
            return 1
        fi
    done
    printf '%s' "$out"
}

# ── HKDF-SHA256 (RFC 5869), explicit extract-then-expand ────────────────
# Implemented in python's hashlib/hmac rather than via a library helper so
# the derivation is inspectable: PRK = HMAC(salt, IKM) and
# T(i) = HMAC(PRK, T(i-1) || info || i).
suci_hkdf() {
    local ikm_hex="${1:-}" salt_hex="${2:-}" info="${3:-}" len="${4:-32}"
    [[ "$ikm_hex" =~ ^([0-9a-fA-F]{2})*$ ]] || {
        printf 'ERROR\tIKM must be hex\n' >&2; return 2; }
    [[ "$salt_hex" =~ ^([0-9a-fA-F]{2})*$ ]] || {
        printf 'ERROR\tsalt must be hex (use an empty string for the RFC 5869 zero-salt case)\n' >&2; return 2; }
    [[ "$len" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    (( len >= 1 && len <= 8160 )) || {
        printf 'ERROR\tHKDF output length must be 1..8160 octets (255*32)\n' >&2; return 2; }
    suci_have_python || { printf 'ERROR\tpython3 is required for HKDF-SHA256\n' >&2; return 1; }
    python3 - "$ikm_hex" "$salt_hex" "$info" "$len" << 'PYEOF'
import sys, hmac, hashlib, binascii
ikm  = binascii.unhexlify(sys.argv[1])
salt = binascii.unhexlify(sys.argv[2]) if sys.argv[2] else b"\x00" * 32
# info is hex when it looks like hex, otherwise literal text.
info_s = sys.argv[3].strip()
try:
    info = binascii.unhexlify(info_s) if info_s else b""
except Exception:
    info = info_s.encode()
L    = int(sys.argv[4])
# Extract
prk = hmac.new(salt, ikm, hashlib.sha256).digest()
# Expand
okm = b""
t   = b""
i   = 1
while len(okm) < L:
    t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
    okm += t
    i += 1
print("prk\t" + prk.hex())
print("okm\t" + okm[:L].hex())
print("hash\tsha256")
print("hash_len\t32")
print("l\t%d" % L)
print("n\t%d" % ((L + 31) // 32))
PYEOF
}

# ── SUCI structure (TS 23.003 §2.2) ─────────────────────────────────────
# The SUCI is an E.164-style identity carried in the NAS as a 5GS mobile
# identity. Its content octets are:
#   octet 1   : SUPI format (bits 1-3) + type of identity (bits 4-6)
#               0 = IMSI, 1 = network-specific identifier
#   octet 2..: the SUPI-protection fields
#     octets 2-3 : home network public key identifier (1 octet) and
#                  the protection scheme identifier (low nibble)
#     octet 4    : routing indicator (2 octets, BCD, high nibble first)
#     then       : the scheme output (MSIN for scheme 0, ciphertext otherwise)
suci_scheme_name() {
    case "${1:-}" in
        0) echo "null-scheme (MSIN in the clear)" ;;
        1) echo "ECIES profile A (X25519)" ;;
        2) echo "ECIES profile B (secp256r1)" ;;
        3) echo "ECIES profile B with extended key id" ;;
        *) echo "unknown" ;;
    esac
}

suci_supi_type_name() {
    case "${1:-}" in
        0) echo "IMSI" ;;
        1) echo "network-specific identifier" ;;
        *) echo "unknown" ;;
    esac
}

# Parse a SUCI from its hex encoding. Returns the structured fields and, for
# scheme 0, the recovered MSIN — which is the whole point of the audit.

# The home-network identifier is the PLMN a real SUCI carries ahead of the
# routing indicator: MCC and MNC in the same BCD packing the IMSI uses
# (TS 23.003 2.2, the PLMN is three octets: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1,
# with 0xF standing in for the third MNC digit when the MNC has two).
suci_plmn_encode() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || {
        printf 'ERROR\tMCC must be exactly 3 digits: %s\n' "$(suci_sanitize "$mcc")" >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || {
        printf 'ERROR\tMNC must be 2 or 3 digits: %s\n' "$(suci_sanitize "$mnc")" >&2; return 2; }
    local d1="${mcc:0:1}" d2="${mcc:1:1}" d3="${mcc:2:1}"
    local m1="${mnc:0:1}" m2="${mnc:1:1}" m3=f
    (( ${#mnc} == 3 )) && m3="${mnc:2:1}"
    printf '%s%s%s%s%s%s' "$d2" "$d1" "$m3" "$d3" "$m2" "$m1"
}

suci_plmn_decode() {
    local hex="${1:-}"
    [[ "$hex" =~ ^[0-9A-Fa-f]{6}$ ]] || return 1
    hex="${hex^^}"
    local mcc mnc m3
    mcc="${hex:1:1}${hex:0:1}${hex:3:1}"
    m3="${hex:2:1}"
    mnc="${hex:5:1}${hex:4:1}"
    [[ "$m3" != "F" ]] && mnc+="$m3"
    printf '%s\t%s' "$mcc" "$mnc"
}

# Which field layout a SUCI is in. "hnid" is what a network sends (home network
# identifier, routing indicator, scheme, key id, output); "compact" is the
# layout this module shipped first, which carries no home network identifier at
# all and so cannot say which network the subscriber belongs to.
suci_layout_of() {
    local hex="${1:-}" layout="${2:-auto}"
    hex="${hex//[[:space:]]/}"; hex="${hex//0x/}"; hex="${hex,,}"
    case "$layout" in
        compact|hnid) printf '%s' "$layout"; return 0 ;;
        auto) ;;
        *) printf 'ERROR\tlayout must be auto, hnid or compact: %s\n' "$(suci_sanitize "$layout")" >&2
           return 2 ;;
    esac
    # A home network identifier plus a scheme octet needs 8 header octets, so
    # anything shorter than 9 octets cannot be the hnid layout.
    if (( ${#hex} < 18 )); then printf 'compact'; return 0; fi
    # In the hnid layout the scheme sits in the low nibble of octet 7 and the
    # key identifier in octet 8; a null/profile A/profile B scheme is 0..2.
    local sch=$(( 16#${hex:12:2} ))
    if (( (sch & 0x0F) <= 2 )); then printf 'hnid'; else printf 'compact'; fi
}

suci_parse() {
    local hex="${1:-}" lay="${2:-auto}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    hex="${hex,,}"
    [[ "$hex" =~ ^[0-9a-f]+$ ]] || {
        printf 'ERROR\tSUCI must be hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || {
        printf 'ERROR\tSUCI must be a whole number of octets\n' >&2; return 1; }
    # Minimum is the 5-octet protection header plus at least one octet of
    # scheme output (a 1-digit MSIN under the null scheme). The hnid layout
    # carries three more octets in front of the routing indicator.
    (( ${#hex} >= 12 )) || {
        printf 'ERROR\tSUCI too short to be well formed (%d octets, need >= 6)\n' "$(( ${#hex} / 2 ))" >&2
        return 1; }

    # Two layouts, and they are not interchangeable:
    #
    # hnid (what a network actually sends, TS 23.003 §2.2 with TS 24.501
    # §9.11.3.4 for the identity octet):
    #   octet 1 : SUPI format (bits 1-3) | type of identity (bits 4-6)
    #   octets 2-4: home network identifier, MCC/MNC in PLMN BCD
    #   octets 5-6: routing indicator
    #   octet 7 : protection scheme identifier (low nibble)
    #   octet 8 : home network public key identifier
    #   octet 9+: scheme output
    #
    # compact (the layout this module shipped first, and the only one it could
    # build): the same fields with the home network identifier missing, so
    # there is nothing in the octets that says which network the subscriber
    # belongs to and every field sits three octets early.
    local layout; layout=$(suci_layout_of "$hex" "$lay") || return 2
    local b0=$(( 16#${hex:0:2} ))
    local supi_type=$(( b0 & 0x07 ))
    local id_type=$(( (b0 >> 3) & 0x07 ))
    local hnkey ri1 ri2 ri3 ri4 scheme scheme_out
    local plmn_hex="" hn_mcc="" hn_mnc=""
    if [[ "$layout" == "hnid" ]]; then
        plmn_hex="${hex:2:6}"
        local pl; pl=$(suci_plmn_decode "$plmn_hex") || {
            printf 'ERROR\thome network identifier %s is not a PLMN in BCD\n' "$(suci_sanitize "$plmn_hex")" >&2
            return 1; }
        hn_mcc="${pl%%$'\t'*}"; hn_mnc="${pl#*$'\t'}"
        ri1=$(( (16#${hex:8:2} >> 4) & 0xF ))
        ri2=$(( 16#${hex:8:2} & 0xF ))
        ri3=$(( (16#${hex:10:2} >> 4) & 0xF ))
        ri4=$(( 16#${hex:10:2} & 0xF ))
        scheme=$(( 16#${hex:12:2} & 0x0F ))
        hnkey=$(( 16#${hex:14:2} ))
        scheme_out="${hex:16}"
    else
        hnkey=$(( 16#${hex:2:2} ))
        ri1=$(( (16#${hex:4:2} >> 4) & 0xF ))
        ri2=$(( 16#${hex:4:2} & 0xF ))
        ri3=$(( (16#${hex:6:2} >> 4) & 0xF ))
        ri4=$(( 16#${hex:6:2} & 0xF ))
        scheme=$(( 16#${hex:8:2} & 0x0F ))
        scheme_out="${hex:10}"
    fi
    (( ${#scheme_out} >= 2 )) || {
        printf 'ERROR\tSUCI too short for the %s layout (%d octets)\n' "$layout" "$(( ${#hex} / 2 ))" >&2
        return 1; }
    local ri=""
    local d
    for d in "$ri1" "$ri2" "$ri3" "$ri4"; do
        [[ "$d" == "15" ]] && continue
        ri+="$d"
    done
    [[ -n "$ri" ]] || ri="0000"

    printf 'layout\t%s\n'             "$layout"
    if [[ -n "$plmn_hex" ]]; then
        printf 'home_network_identifier\t%s\n' "$plmn_hex"
        printf 'home_mcc\t%s\n'         "$hn_mcc"
        printf 'home_mnc\t%s\n'         "$hn_mnc"
    else
        printf 'home_network_identifier\tabsent\n'
        printf 'finding\tno home network identifier in the octets: this is the compact layout, which cannot say which network the subscriber belongs to\n'
    fi
    printf 'supi_type\t%s\n'          "$supi_type"
    printf 'supi_type_name\t%s\n'     "$(suci_supi_type_name "$supi_type")"
    printf 'identity_type\t%s\n'      "$id_type"
    printf 'hn_public_key_id\t%s\n'   "$hnkey"
    printf 'protection_scheme\t%s\n'  "$scheme"
    printf 'scheme_name\t%s\n'        "$(suci_scheme_name "$scheme")"
    printf 'routing_indicator\t%s\n'  "$ri"
    printf 'scheme_output\t%s\n'      "$scheme_out"
    printf 'scheme_output_octets\t%s\n' "$(( ${#scheme_out} / 2 ))"

    case "$scheme" in
        0)
            # The null scheme carries the BCD MSIN with no protection at all.
            printf 'msin_exposed\tyes\n'
            local msin
            if msin=$(suci_msin_decode "$scheme_out" 2>/dev/null); then
                printf 'msin\t%s\n' "$msin"
                printf 'imsi\t%s\n' "$msin"
            else
                printf 'msin\tunparseable\n'
            fi
            printf 'finding\tMSIN transmitted in the clear (null scheme): the SUCI provides no privacy\n'
            ;;
        1)
            printf 'msin_exposed\tno\n'
            printf 'ephemeral_key_octets\t32\n'
            if (( ${#scheme_out} >= 64 )); then
                printf 'ephemeral_public_key\t%s\n' "${scheme_out:0:64}"
                printf 'ciphertext\t%s\n' "${scheme_out:64}"
            fi
            ;;
        2|3)
            printf 'msin_exposed\tno\n'
            printf 'ephemeral_key_octets\t33\n'
            if (( ${#scheme_out} >= 66 )); then
                printf 'ephemeral_public_key\t%s\n' "${scheme_out:0:66}"
                printf 'ciphertext\t%s\n' "${scheme_out:66}"
            fi
            ;;
        *)
            printf 'msin_exposed\tunknown\n'
            ;;
    esac
    return 0
}

# ── profile A / B concealment and deconcealment ─────────────────────────
# TS 33.501 Annex C.2/C.3. The scheme is ECIES:
#   1. the UE generates an ephemeral key pair on the curve
#   2. shared = ECDH(eph_priv, HN_pub)
#   3. K = HKDF-SHA256(IKM=shared, salt=eph_pub, info=eph_pub || HN_pub)
#   4. the MSIN (BCD encoded) is encrypted with AES-128-CTR, ICB = 0^127||1
#   5. scheme output = eph_pub || ciphertext
# Profile A uses X25519; profile B uses secp256r1 with a compressed point.
suci_conceal() {
    local scheme="${1:-1}" msin="${2:-}" hn_pub_hex="${3:-}"
    [[ "$scheme" =~ ^[12]$ ]] || {
        printf 'ERROR\tscheme must be 1 (profile A) or 2 (profile B)\n' >&2; return 2; }
    [[ -n "$msin" ]] || { printf 'ERROR\tMSIN required\n' >&2; return 2; }
    [[ -n "$hn_pub_hex" ]] || { printf 'ERROR\t home network public key required (hex)\n' >&2; return 2; }
    local dep; dep=$(suci_missing_dep)
    if [[ -n "$dep" ]]; then
        printf 'ERROR\t%s is required for profile A/B concealment\n' "$dep" >&2
        return 1
    fi
    local bcd; bcd=$(suci_msin_encode "$msin") || return 2
    python3 - "$scheme" "$bcd" "$hn_pub_hex" << 'PYEOF'
import sys, binascii, hashlib, hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

scheme = int(sys.argv[1])
bcd    = binascii.unhexlify(sys.argv[2])
hn_pub = binascii.unhexlify(sys.argv[3])

def hkdf(ikm, salt, info, length=16):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:length]

if scheme == 1:
    if len(hn_pub) != 32:
        sys.exit("ERROR\tprofile A home network public key must be 32 bytes (X25519)")
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(hn_pub))
else:
    if len(hn_pub) != 33:
        sys.exit("ERROR\tprofile B home network public key must be 33 bytes (compressed P-256)")
    curve = ec.SECP256R1()
    hn = ec.EllipticCurvePublicKey.from_encoded_point(curve, hn_pub)
    eph = ec.generate_private_key(curve)
    eph_pub = eph.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.X962,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.CompressedPoint)
    shared = eph.exchange(ec.ECDH(), hn)

info = eph_pub + hn_pub
k = hkdf(shared, eph_pub, info, 16)
icb = b"\x00" * 15 + b"\x01"
enc = Cipher(algorithms.AES(k), modes.CTR(icb)).encryptor()
ct = enc.update(bcd) + enc.finalize()
print("scheme\t%d" % scheme)
print("ephemeral_public_key\t" + eph_pub.hex())
print("shared_secret\t" + shared.hex())
print("k_hex\t" + k.hex())
print("icb\t" + icb.hex())
print("bcd_msin\t" + bcd.hex())
print("ciphertext\t" + ct.hex())
print("scheme_output\t" + (eph_pub + ct).hex())
PYEOF
}

# ── the home-network key interface ──────────────────────────────────────
# This is the last hop of SUCI deconcealment: everything above is real and
# testable offline, but recovering a subscriber's MSIN needs the home
# network's private key for the profile that concealed it. There is no way
# to compute past that key, and this module will not pretend otherwise.
#
# The key arrives at exactly one place:
#
#   --deconceal <suci-hex> <key>   second argument, tried in this order:
#       1. 64 hex digits (optionally 0x-prefixed, whitespace tolerated)
#          = a raw 32-octet private scalar, as --genkey prints it
#       2. a path to a readable file, in any of:
#            - the key file --genkey writes (comment header + TSV, the
#              private_key field is used)
#            - a file whose only content is the hex scalar
#            - a standard PEM/DER key: PKCS#8, SEC1, OpenSSH, X25519 or P-256
#
#   IMSISTING_SUCI_HN_KEY=<path>   used when the second argument is omitted;
#                                  must name an existing readable file
#
# The key is validated against the profile the SUCI actually used: the curve
# must be right, the encoding right, the length right, and the scalar a valid
# key on that curve. Every failure is a distinct non-zero exit with an
# actionable message; there is no fallback path and no weaker scheme is
# substituted. Exit codes (they do not collide with the pass/fail contract the
# launcher reads):
#
#   0  key resolved and validated
#   2  missing      no key supplied, or the file/variable names nothing
#   1  malformed    hex that will not parse, a corrupt PEM/DER, or a key file
#                   with no private key field
#   3  unreadable   the path exists but this user cannot read it, or is not a
#                   regular file
#   4  wrong-curve  a valid key that is not the curve the profile requires
#
# suci_key_error prints the actionable message for one of those codes.
suci_key_error() {
    case "${1:-}" in
        2) printf 'ERROR\tno home-network private key: pass <suci-hex> <key-hex|keyfile> or set IMSISTING_SUCI_HN_KEY to a key file (see --status-tsv)\n' >&2 ;;
        1) printf 'ERROR\thome-network private key is malformed: supply a 64-hex-digit private scalar, a --genkey key file, or a PEM/DER key file\n' >&2 ;;
        3) printf 'ERROR\thome-network private key is unreadable: the path exists but cannot be opened as a regular file by this user\n' >&2 ;;
        4) printf 'ERROR\thome-network private key is the wrong curve for this SUCI: profile A (scheme 1) needs X25519, profile B (schemes 2/3) needs secp256r1 (P-256)\n' >&2 ;;
        *) printf 'ERROR\thome-network private key could not be resolved\n' >&2 ;;
    esac
}

# Resolve one key source (an existing file, or 64 hex digits) to
#   private_key <hex>  public_key <hex>  curve <name>  encoding <label>
# The profile argument is required, so the curve is checked against the
# profile that actually concealed the SUCI rather than guessed from the key.
suci_key_resolve_source() {
    local src="${1:-}" profile="${2:-}"
    [[ -n "$src" ]] || return 2
    [[ "$profile" == "1" || "$profile" == "2" ]] || return 4
    local dep; dep=$(suci_missing_dep)
    if [[ -n "$dep" ]]; then
        printf 'ERROR\t%s is required to validate a home-network private key\n' "$dep" >&2
        return 1
    fi
    local mode="hex" path=""
    # A hex string is unambiguous, so it wins over a same-named file.
    if [[ "$src" =~ ^(0x)?[0-9a-fA-F]{64}$ ]]; then
        mode="hex"; path="$src"
    elif [[ -e "$src" ]]; then
        mode="file"; path="$src"
        if [[ ! -f "$path" ]]; then
            printf 'ERROR\thome-network private key path is not a regular file: %s\n' "$(suci_sanitize "$path")" >&2
            return 3
        fi
        if [[ ! -r "$path" ]]; then
            printf 'ERROR\thome-network private key file is not readable by this user: %s\n' "$(suci_sanitize "$path")" >&2
            return 3
        fi
        [[ -s "$path" ]] || {
            printf 'ERROR\thome-network private key file is empty: %s\n' "$(suci_sanitize "$path")" >&2
            return 1; }
    else
        printf 'ERROR\thome-network private key is neither 64 hex digits nor an existing file: %s\n' "$(suci_sanitize "$src")" >&2
        return 1
    fi
    python3 - "$mode" "$path" "$profile" << 'PYEOF'
import sys, re, base64, binascii
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization as ser

mode, path, profile = sys.argv[1], sys.argv[2], int(sys.argv[3])

def fail(msg):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(90)

def der_priv(data):
    """Load a private key from PKCS#8 or SEC1 DER."""
    try:
        return ser.load_der_private_key(data, password=None)
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        return _ec.derive_private_key(int.from_bytes(data, "big"), _ec.SECP256R1())
    except Exception:
        return None

raw = None          # a 32-octet scalar whose curve the container did not say
obj = None          # a key object whose curve the container *did* say (PEM/DER)
enc = "raw-hex"

def key_from_raw(scalar, prof):
    """Build the private key a curve-agnostic 32-octet scalar denotes.

    A bare scalar carries no curve, so the profile that concealed the SUCI
    decides how to read it -- otherwise a valid P-256 scalar would be
    misreported as a wrong-curve X25519 key. An out-of-range P-256 scalar is
    malformed, not wrong-curve: the bytes are not a key at all.
    """
    if prof == 1:
        return x25519.X25519PrivateKey.from_private_bytes(scalar), "X25519"
    # 2^256 is a safe upper bound that needs no big-int curve-parameter copy;
    # the curve order check is the one that actually rejects a bad scalar.
    d = int.from_bytes(scalar, "big")
    if d == 0:
        fail("private key is not a valid secp256r1 scalar (zero or out of range)")
    try:
        return ec.derive_private_key(d, ec.SECP256R1()), "secp256r1"
    except ValueError as e:
        fail("private key is not a valid secp256r1 scalar: %s" % e)

def octets_of(key):
    """The private scalar of a parsed key, so both containers normalise."""
    if isinstance(key, x25519.X25519PrivateKey):
        return key.private_bytes_raw()
    return key.private_numbers().private_value.to_bytes(32, "big")

if mode == "hex":
    raw = binascii.unhexlify(path)
else:
    try:
        blob = open(path, "rb").read()
    except OSError as e:
        sys.stderr.write("ERROR\tcannot read the home-network private key file: %s\n" % e)
        sys.exit(91)
    if not blob.strip():
        fail("key file has no content")
    text = None
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        # 1. the key file --genkey writes: comments, then TSV fields.
        val = None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                k, _, v = line.partition("\t")
                if k.strip() == "private_key":
                    val = v.strip(); break
            elif re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", line):
                val = line; break
        if val is not None:
            val = val[2:] if val.lower().startswith("0x") else val
            if not re.fullmatch(r"[0-9a-fA-F]{64}", val):
                fail("the private_key field is not 64 hex digits")
            raw = binascii.unhexlify(val)
            enc = "tsv-hex" if "\t" in text else "hex-file"
        elif "BEGIN" in text and "PRIVATE KEY" in text:
            try:
                obj = ser.load_pem_private_key(text.encode(), password=None)
            except Exception as e:
                fail("PEM private key could not be parsed: %s" % e)
            enc = "pem"
        else:
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            if len(lines) == 1 and re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", lines[0]):
                v = lines[0]
                v = v[2:] if v.lower().startswith("0x") else v
                raw = binascii.unhexlify(v)
                enc = "hex-file"
            else:
                compact = re.sub(r"\s+", "", text)
                try:
                    obj = der_priv(base64.b64decode(compact, validate=True))
                    if obj is not None:
                        enc = "der-base64"
                except Exception:
                    obj = None
                if obj is None:
                    obj = der_priv(blob)
                    if obj is not None:
                        enc = "der"
    else:
        # Binary: a PEM that was not text, or a bare DER key.
        if b"BEGIN" in blob and b"PRIVATE KEY" in blob:
            try:
                obj = ser.load_pem_private_key(blob, password=None)
                enc = "pem"
            except Exception as e:
                fail("PEM private key could not be parsed: %s" % e)
        if obj is None:
            obj = der_priv(blob)
            if obj is not None:
                enc = "der"

if obj is None and raw is None:
    fail("key file has no private key this interface recognises (hex scalar, --genkey TSV, PEM or DER)")

if obj is not None:
    # The container named the curve, so a mismatch is a real wrong-curve answer.
    if isinstance(obj, x25519.X25519PrivateKey):
        curve = "X25519"
    elif isinstance(obj, ec.EllipticCurvePrivateKey):
        if not isinstance(obj.curve, ec.SECP256R1):
            fail("private key is on curve %s, not secp256r1" % obj.curve.name)
        curve = "secp256r1"
    else:
        fail("unsupported private key type: %s" % type(obj).__name__)
    kp = obj
    raw = octets_of(obj)
    want = "X25519" if profile == 1 else "secp256r1"
    if curve != want:
        sys.stderr.write(
            "ERROR\tprivate key is %s but profile %d needs %s\n" % (curve, profile, want))
        sys.exit(4)
else:
    if len(raw) != 32:
        fail("private key is %d octets, expected 32" % len(raw))
    kp, curve = key_from_raw(bytes(raw), profile)

hn_pub = (kp.public_key().public_bytes_raw() if curve == "X25519"
          else kp.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint))

priv = (kp.private_bytes_raw() if curve == "X25519"
        else kp.private_numbers().private_value.to_bytes(32, "big"))
print("private_key\t" + priv.hex())
print("public_key\t" + hn_pub.hex())
print("hn_public_key\t" + hn_pub.hex())
print("curve\t" + curve)
print("encoding\t" + enc)
print("profile\t%d" % profile)
PYEOF
}

# The documented entry point. An explicit argument wins; otherwise
# IMSISTING_SUCI_HN_KEY supplies a key file. Nothing is guessed and no
# default key file is picked up behind the operator's back.
suci_key_resolve() {
    local arg="${1:-}" profile="${2:-}"
    local src="$arg" origin="argument"
    if [[ -z "$src" ]]; then
        if [[ -n "${IMSISTING_SUCI_HN_KEY:-}" ]]; then
            src="$IMSISTING_SUCI_HN_KEY"; origin="env:IMSISTING_SUCI_HN_KEY"
        else
            printf 'ERROR\tno home-network private key supplied (second argument or IMSISTING_SUCI_HN_KEY)\n' >&2
            return 2
        fi
    fi
    local out rc=0 err=""
    err=$(mktemp "$MOD_TMP/keyerr.XXXXXX" 2>/dev/null) || err="$MOD_TMP/keyerr.$$"
    out=$(suci_key_resolve_source "$src" "$profile" 2>"$err") || rc=$?
    if (( rc == 0 )); then
        rm -f "$err"
        printf '%s\n' "$out"
        printf 'key_source\t%s\n' "$origin"
        printf 'key_ref\t%s\n' "$(suci_sanitize "$src")"
        return 0
    fi
    # Report the resolver's specific complaint, not a generic one.
    if [[ -s "$err" ]]; then sed -n '1p' "$err" >&2; else suci_key_error "$rc"; fi
    rm -f "$err"
    # Collapse the parser's internal exits onto the documented code set.
    case "$rc" in
        2|3|4) return "$rc" ;;
        *)     return 1 ;;
    esac
}

# ── the reverse direction: given the home network private key and a captured
# SUCI, recover the MSIN. This is the operator's own key — an audit tool that
# cannot run it cannot tell whether a deployment is actually protecting the
# subscriber.
suci_deconceal() {
    local suci_hex="${1:-}" priv_hex="${2:-}"
    [[ -n "$suci_hex" && -n "$priv_hex" ]] || {
        printf 'ERROR\tusage: --deconceal <suci-hex> <hn-private-key-hex>\n' >&2; return 2; }
    local dep; dep=$(suci_missing_dep)
    if [[ -n "$dep" ]]; then
        printf 'ERROR\t%s is required for deconcealment\n' "$dep" >&2
        return 1
    fi
    suci_hex="${suci_hex//[[:space:]]/}"; suci_hex="${suci_hex//0x/}"
    [[ "$suci_hex" =~ ^[0-9a-fA-F]+$ ]] || { printf 'ERROR\tSUCI must be hex\n' >&2; return 1; }

    local scheme; scheme=$(suci_parse "$suci_hex" 2>/dev/null | awk -F'\t' '$1=="protection_scheme"{print $2}')
    [[ -n "$scheme" ]] || { printf 'ERROR\tcould not parse the SUCI\n' >&2; return 1; }
    if (( scheme == 0 )); then
        printf 'ERROR\tscheme 0 (null) needs no key: the MSIN is already in the clear, use --parse-suci\n' >&2
        return 1
    fi
    local scheme_out
    scheme_out=$(suci_parse "$suci_hex" | awk -F'\t' '$1=="scheme_output"{print $2}')

    # The key arrives through the one documented interface, validated against
    # the profile this SUCI used (1 or 2). A refused key stops here: no
    # fallback, no weaker path, no attempt with a key that does not fit.
    local kprof="$scheme"; [[ "$scheme" == "3" ]] && kprof=2
    local kout krc=0
    kout=$(suci_key_resolve "$priv_hex" "$kprof") || krc=$?
    if (( krc != 0 )); then
        (( krc == 2 || krc == 3 || krc == 4 )) || krc=1
        return "$krc"
    fi
    local priv_hex2 hn_pub
    priv_hex2=$(printf '%s\n' "$kout" | awk -F'\t' '$1=="private_key"{print $2; exit}')
    hn_pub=$(printf '%s\n' "$kout" | awk -F'\t' '$1=="public_key"{print $2; exit}')
    [[ -n "$priv_hex2" && -n "$hn_pub" ]] || {
        printf 'ERROR\thome-network key interface returned no key material\n' >&2; return 1; }

    python3 - "$scheme" "$scheme_out" "$priv_hex2" "$hn_pub" << 'PYEOF'
import sys, binascii, hashlib, hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

scheme  = int(sys.argv[1])
out     = binascii.unhexlify(sys.argv[2])
priv    = binascii.unhexlify(sys.argv[3])
hn_pub  = binascii.unhexlify(sys.argv[4])

def hkdf(ikm, salt, info, length=16):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t; i += 1
    return okm[:length]

# The public key was derived by the key interface from the private key, so it
# is a function of the key and not an independent input; asserting it here
# would only re-check the interface's own arithmetic.
if scheme == 1:
    if len(out) < 32:
        sys.exit("ERROR\tscheme output too short for a 32-byte ephemeral key")
    eph_pub, ct = out[:32], out[32:]
    kp = x25519.X25519PrivateKey.from_private_bytes(priv)
    shared = kp.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
else:
    if len(out) < 33:
        sys.exit("ERROR\tscheme output too short for a 33-byte ephemeral key")
    eph_pub, ct = out[:33], out[33:]
    curve = ec.SECP256R1()
    kp = ec.derive_private_key(int.from_bytes(priv, "big"), curve)
    eph = ec.EllipticCurvePublicKey.from_encoded_point(curve, eph_pub)
    shared = kp.exchange(ec.ECDH(), eph)

info = eph_pub + hn_pub
k = hkdf(shared, eph_pub, info, 16)
icb = b"\x00" * 15 + b"\x01"
dec = Cipher(algorithms.AES(k), modes.CTR(icb)).decryptor()
pt = dec.update(ct) + dec.finalize()
# The plaintext is the BCD MSIN; an odd digit count leaves 0xF filler.
# BCD decode, per TS 23.003 2.2: in each octet the LOW nibble holds the
# first digit of the pair and the HIGH nibble the second; the 0xF filler
# appears in the HIGH nibble of the final octet when the count is odd.
# pt is bytes, so iterate over every octet (stepping by 2 would skip half).
digits = ""
for idx, byte in enumerate(pt):
    lo = byte & 0x0F
    hi = (byte >> 4) & 0x0F
    if lo > 9:
        sys.exit("ERROR\tdecrypted BCD low nibble is not a decimal digit; wrong key?")
    digits += str(lo)
    if hi == 0xF:
        if idx != len(pt) - 1:
            sys.exit("ERROR\tBCD filler in a non-final octet; wrong key?")
    elif hi > 9:
        sys.exit("ERROR\tdecrypted BCD high nibble is not a decimal digit; wrong key?")
    else:
        digits += str(hi)
print("scheme\t%d" % scheme)
print("ephemeral_public_key\t" + eph_pub.hex())
print("hn_public_key\t" + hn_pub.hex())
print("shared_secret\t" + shared.hex())
print("k_hex\t" + k.hex())
print("bcd_msin\t" + pt.hex())
print("msin\t" + digits)
print("msin_digits\t%d" % len(digits))
PYEOF
}

# Generate a home network key pair for a lab deployment, so the profile A/B
# round trip can actually be exercised end to end.
suci_gen_keypair() {
    local scheme="${1:-1}"
    [[ "$scheme" =~ ^[12]$ ]] || {
        printf 'ERROR\tscheme must be 1 (profile A) or 2 (profile B)\n' >&2; return 2; }
    local dep; dep=$(suci_missing_dep)
    if [[ -n "$dep" ]]; then
        printf 'ERROR\t%s is required to generate a key pair\n' "$dep" >&2
        return 1
    fi
    python3 - "$scheme" << 'PYEOF'
import sys
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization as ser
scheme = int(sys.argv[1])
if scheme == 1:
    kp = x25519.X25519PrivateKey.generate()
    priv = kp.private_bytes_raw()
    pub  = kp.public_key().public_bytes_raw()
    curve = "X25519"
else:
    kp = ec.generate_private_key(ec.SECP256R1())
    priv = kp.private_numbers().private_value.to_bytes(32, "big")
    pub  = kp.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
    curve = "secp256r1"
print("scheme\t%d" % scheme)
print("curve\t" + curve)
print("private_key\t" + priv.hex())
print("public_key\t" + pub.hex())
print("public_key_octets\t%d" % len(pub))
PYEOF
}

# ── attack surface ──────────────────────────────────────────────────────
# An audit reads a file of SUCI strings (one hex per line, blank lines and
# # comments ignored) and reports the concrete weaknesses it can prove from
# the data alone:
#   - a null-scheme SUCI (scheme 0) exposes the MSIN outright
#   - a repeated ephemeral public key across SUCIs breaks unlinkability,
#     because the same ephemeral key means the same UE can be correlated
#     even though the SUPI is concealed
suci_audit() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --audit <sucis-file>\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$file" >&2; return 1; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read: %s\n' "$file" >&2; return 1; }

    local total=0 nulls=0 profiles=0 bad=0
    local out="$MOD_TMP/audit_schemes.txt"
    : > "$out"
    local line
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        line="${line//0x/}"
        [[ -z "$line" ]] && continue
        total=$(( total + 1 ))
        local parsed scheme epk
        parsed=$(suci_parse "$line" 2>/dev/null) || {
            bad=$(( bad + 1 )); printf 'BAD\t%s\n' "$(suci_sanitize "$line")" >> "$out"; continue; }
        scheme=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="protection_scheme"{print $2}')
        epk=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="ephemeral_public_key"{print $2}')
        case "$scheme" in
            0) nulls=$(( nulls + 1 )) ;;
            1|2|3) profiles=$(( profiles + 1 )) ;;
        esac
        printf '%s\t%s\t%s\n' "$scheme" "${epk:-none}" "$(suci_sanitize "$line")" >> "$out"
    done < "$file"

    [[ "$total" -gt 0 ]] || { printf 'ERROR\tno SUCI records found in %s\n' "$(suci_sanitize "$file")" >&2; return 1; }

    printf 'file\t%s\n' "$(suci_sanitize "$file")"
    printf 'sucis\t%s\n' "$total"
    printf 'null_scheme\t%s\n' "$nulls"
    printf 'concealed\t%s\n' "$profiles"
    printf 'unparseable\t%s\n' "$bad"

    if (( nulls > 0 )); then
        printf 'finding\tnull-scheme-suci\n'
        printf 'finding_detail\t%s of %s SUCIs use scheme 0: the MSIN is in the clear and the subscriber is identified\n' \
            "$nulls" "$total"
    fi

    # Repeated ephemeral public keys: only meaningful for concealed SUCIs.
    local dupes
    dupes=$(awk -F'\t' '$1!="0" && $2!="none" && $2!="" {print $2}' "$out" | sort | uniq -d)
    if [[ -n "$dupes" ]]; then
        local n; n=$(printf '%s\n' "$dupes" | grep -c .)
        printf 'reused_ephemeral_keys\t%s\n' "$n"
        printf 'finding\treused-ephemeral-key\n'
        printf 'finding_detail\t%s ephemeral public key(s) appear more than once: those SUCIs are linkable to the same UE\n' "$n"
        local k
        while IFS= read -r k; do
            [[ -z "$k" ]] && continue
            printf 'reused_key\t%s\tcount=%s\n' "$(suci_sanitize "$k")" \
                "$(awk -F'\t' -v k="$k" '$2==k' "$out" | wc -l)"
        done <<< "$dupes"
    else
        printf 'reused_ephemeral_keys\t0\n'
    fi

    # A concrete answer rather than a summary: is this deployment protecting
    # the subscriber, or is the SUCI decorative?
    if (( nulls > 0 )); then
        printf 'verdict\tEXPOSED\n'
    elif [[ -n "$dupes" ]]; then
        printf 'verdict\tLINKABLE\n'
    elif (( bad > 0 )); then
        printf 'verdict\tPARTIAL\n'
    else
        printf 'verdict\tCONCEALED\n'
    fi
}

suci_build() {
    local scheme="${1:-1}" msin="${2:-}" hn_pub="${3:-}" mcc="${4:-001}" mnc="${5:-01}"
    local hnkey="${6:-1}" ri="${7:-0000}" layout="${8:-hnid}"
    case "$layout" in
        hnid|compact) ;;
        *) printf 'ERROR\tlayout must be hnid or compact: %s\n' "$(suci_sanitize "$layout")" >&2; return 2 ;;
    esac
    [[ "$scheme" =~ ^[012]$ ]] || {
        printf 'ERROR\tscheme must be 0 (null), 1 (profile A) or 2 (profile B)\n' >&2; return 2; }
    [[ -n "$msin" ]] || { printf 'ERROR\tMSIN required\n' >&2; return 2; }
    local bcd; bcd=$(suci_msin_encode "$msin") || return 2

    local scheme_out=""
    if (( scheme == 0 )); then
        scheme_out="$bcd"
    else
        [[ -n "$hn_pub" ]] || {
            printf 'ERROR\tscheme %s needs a home network public key\n' "$scheme" >&2; return 2; }
        local enc; enc=$(suci_conceal "$scheme" "$msin" "$hn_pub") || return 1
        scheme_out=$(printf '%s\n' "$enc" | awk -F'\t' '$1=="scheme_output"{print $2}')
        [[ -n "$scheme_out" ]] || { printf 'ERROR\tconcealment produced no scheme output\n' >&2; return 1; }
    fi

    # Assemble the SUCI: SUPI format (IMSI = 0, low 3 bits), identity type
    # (SUCI = 1, bits 4-6), then the protection fields.
    # SUPI format 0 (IMSI) in bits 1-3, type of identity 1 (SUCI) in bits 4-6.
    local b0; b0=$(( (1 << 3) | 0 ))
    local ri_bcd; ri_bcd=$(suci_ri_encode "$ri") || return 2
    # Validate every numeric field before assembly: printf %02X on an empty
    # string emits 00 and silently shifts the remaining fields, which produced
    # a well-formed-looking SUCI with the scheme in the wrong octet.
    [[ "$hnkey" =~ ^[0-9]+$ ]] && (( hnkey >= 0 && hnkey <= 255 )) || {
        printf 'ERROR\thome network public key identifier must be 0..255\n' >&2; return 2; }
    [[ "$ri_bcd" =~ ^[0-9A-Fa-f]{4}$ ]] || {
        printf 'ERROR\trouting indicator encoding failed: %s\n' "$(suci_sanitize "$ri_bcd")" >&2; return 1; }
    [[ -n "$scheme_out" ]] || {
        printf 'ERROR\tscheme output is empty\n' >&2; return 1; }
    local plmn_hex=""
    if [[ "$layout" == "hnid" ]]; then
        plmn_hex=$(suci_plmn_encode "$mcc" "$mnc") || return 2
    fi
    local hex
    if [[ "$layout" == "hnid" ]]; then
        hex=$(printf '%02X%s%s%02X%02X%s' "$b0" "$plmn_hex" "$ri_bcd" "$scheme" "$hnkey" "$scheme_out")
    else
        hex=$(printf '%02X%02X%s%02X%s' "$b0" "$hnkey" "$ri_bcd" "$scheme" "$scheme_out")
    fi
    printf 'suci\t%s\n' "$hex"
    printf 'layout\t%s\n' "$layout"
    printf 'scheme\t%s\n' "$scheme"
    printf 'scheme_name\t%s\n' "$(suci_scheme_name "$scheme")"
    printf 'hn_public_key_id\t%s\n' "$hnkey"
    printf 'routing_indicator\t%s\n' "$(suci_sanitize "$ri")"
    printf 'mcc\t%s\n' "$(suci_sanitize "$mcc")"
    printf 'mnc\t%s\n' "$(suci_sanitize "$mnc")"
    if [[ "$layout" == "hnid" ]]; then
        printf 'home_network_identifier\t%s\n' "$plmn_hex"
    else
        printf 'home_network_identifier\tabsent\n'
        printf 'finding\tcompact layout: the SUCI carries no MCC/MNC, so it does not say which network the subscriber belongs to\n'
    fi
    printf 'bcd_msin\t%s\n' "$bcd"
    printf 'scheme_output_octets\t%s\n' "$(( ${#scheme_out} / 2 ))"
    printf 'suci_octets\t%s\n' "$(( ${#hex} / 2 ))"
}

# The routing indicator is 2 BCD octets, each holding two digits with the
# first digit in the high nibble. "0000" (or "0") means not used.
suci_ri_encode() {
    local ri="${1:-0000}"
    [[ "$ri" =~ ^[0-9]{1,4}$ ]] || {
        printf 'ERROR\trouting indicator must be 1..4 decimal digits\n' >&2; return 2; }
    # Two BCD octets, first digit in the high nibble; pad with 0xF.
    while (( ${#ri} < 4 )); do ri+="F"; done
    local d1="${ri:0:1}" d2="${ri:1:1}" d3="${ri:2:1}" d4="${ri:3:1}"
    local o1 o2
    o1=$(suci_ri_nibble "$d1")$(suci_ri_nibble "$d2")
    o2=$(suci_ri_nibble "$d3")$(suci_ri_nibble "$d4")
    printf '%s%s' "$o1" "$o2"
}

# A routing-indicator digit, where "F" is the unused filler.
suci_ri_nibble() {
    case "${1:-}" in
        [0-9]) printf '%s' "$1" ;;
        F|f)   printf 'F' ;;
        *)     printf 'ERROR\tbad routing indicator digit\n' >&2; return 1 ;;
    esac
}

# ── the linkability oracle ──────────────────────────────────────────────
# TS 33.501 conceals the SUPI so that two attach attempts cannot be tied to
# one subscriber. That is a claim about the *whole* observation, not just the
# SUCI octets: an authentication round also exposes the protection scheme, the
# home network's public key identifier, the routing indicator, the length of
# the concealed MSIN, and (when a capture carries them) RAND and AUTN. This
# oracle takes observations of authentication rounds and answers, pair by
# pair, whether anything in them links the two rounds to one subscriber --
# and, when the answer is no, which fields the pair shares anyway because the
# whole home network shares them.
#
# Fields are classified before they are compared, because the classes are what
# the answer depends on:
#   identifying  the pair is one subscriber if these match: the SUCI octets,
#                the ephemeral public key, the MSIN ciphertext, a cleartext
#                MSIN under the null scheme, or an identical AUTN (the same
#                authentication vector reached two observations)
#   weak         the concealed MSIN's length: only its digit count, a class
#                that two subscribers of one operator can easily share
#   herd         scheme, home network public key identifier, routing
#                indicator: every subscriber of that network carries them, so
#                they never identify on their own
suci_link_obs() { # <suci> -> scheme, hnkey, ri, eph, cipher, plain_msin, octets
    local suci="${1:-}" parsed scheme hnkey ri out
    parsed=$(suci_parse "$suci" 2>/dev/null) || return 1
    scheme=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="protection_scheme"{print $2}')
    hnkey=$(printf  '%s\n' "$parsed" | awk -F'\t' '$1=="hn_public_key_id"{print $2}')
    ri=$(printf     '%s\n' "$parsed" | awk -F'\t' '$1=="routing_indicator"{print $2}')
    out=$(printf    '%s\n' "$parsed" | awk -F'\t' '$1=="scheme_output"{print $2}')
    local eph="" cipher="$out" plain=""
    case "$scheme" in
        1) # profile A: a 32-octet X25519 ephemeral public key, then the ciphertext
           if (( ${#out} >= 64 )); then eph="${out:0:64}"; cipher="${out:64}"; fi ;;
        2) # profile B: a 33-octet compressed P-256 ephemeral public key
           if (( ${#out} >= 66 )); then eph="${out:0:66}"; cipher="${out:66}"; fi ;;
        0) # the null scheme: no ephemeral key, the MSIN is in the clear
           plain=$(suci_msin_decode "$out" 2>/dev/null || echo "?") ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$scheme" "${hnkey:-?}" "${ri:-?}" "${eph:-none}" "${cipher:-none}" \
        "${plain:-none}" "$(( ${#out} / 2 ))"
}

suci_link_oracle() { # <observations-file>
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --link-oracle <observations>\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$(suci_sanitize "$file")" >&2; return 1; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read: %s\n' "$(suci_sanitize "$file")" >&2; return 1; }

    local -a lbl=() su=() sch=() hnk=() ri=() eph=() cip=() pln=() oct=() autn=() rnd=()
    local line label suci rest a r fields n=0 bad=0 o_autn="" o_rnd=""
    while IFS= read -r line; do
        line="${line%%#*}"
        # Keep the tab structure: a tab-separated observation carries extra
        # columns, a bare line is a SUCI on its own.
        line="${line%"${line##*[![:space:]]}"}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" ]] && continue
        if [[ "$line" == *$'\t'* ]]; then
            label="${line%%$'\t'*}"
            rest="${line#*$'\t'}"
            suci="${rest%%$'\t'*}"
            rest="${rest#"$suci"}"
            o_autn=""; o_rnd=""
            if [[ -n "$rest" ]]; then
                rest="${rest#$'\t'}"
                o_autn="${rest%%$'\t'*}"
                o_rnd="${rest#"$o_autn"}"
                o_rnd="${o_rnd#$'\t'}"
            fi
        else
            label=""
            suci="$line"
            o_autn=""; o_rnd=""
        fi
        suci="${suci//[[:space:]]/}"
        suci="${suci//0x/}"
        suci="${suci,,}"
        [[ -z "$suci" ]] && continue
        n=$(( n + 1 ))
        [[ -n "$label" ]] || label="obs${n}"
        if ! fields=$(suci_link_obs "$suci"); then
            bad=$(( bad + 1 ))
            printf 'unparseable\t%s\t%s\n' "$(suci_sanitize "$label")" \
                "$(suci_sanitize "${suci:0:40}")"
            continue
        fi
        lbl+=("$(suci_sanitize "$label")")
        su+=("$suci")
        sch+=("$(cut -f1 <<< "$fields")")
        hnk+=("$(cut -f2 <<< "$fields")")
        ri+=("$(cut -f3 <<< "$fields")")
        eph+=("$(cut -f4 <<< "$fields")")
        cip+=("$(cut -f5 <<< "$fields")")
        pln+=("$(cut -f6 <<< "$fields")")
        oct+=("$(cut -f7 <<< "$fields")")
        autn+=("${o_autn,,}")
        rnd+=("${o_rnd,,}")
    done < "$file"

    (( ${#su[@]} > 0 )) || {
        printf 'ERROR\tno parseable observations in %s: %s line(s) rejected\n' \
            "$(suci_sanitize "$file")" "$bad" >&2; return 1; }

    printf 'file\t%s\n' "$(suci_sanitize "$file")"
    printf 'observations\t%s\n' "${#su[@]}"
    printf 'unparseable\t%s\n' "$bad"

    local i j pair=0 linked=0
    local -a findings=()
    for (( i = 0; i < ${#su[@]}; i++ )); do
        for (( j = i + 1; j < ${#su[@]}; j++ )); do
            pair=$(( pair + 1 ))
            local why=() weak=() herd=()
            [[ "${su[i]}" == "${su[j]}" ]]                                    && why+=("suci")
            [[ "${eph[i]}" != "none" && "${eph[i]}" == "${eph[j]}" ]]         && why+=("eph_key")
            [[ "${cip[i]}" != "none" && "${cip[i]}" == "${cip[j]}" ]]         && why+=("msin_ciphertext")
            [[ "${pln[i]}" != "none" && "${pln[i]}" == "${pln[j]}" ]]         && why+=("cleartext_msin")
            [[ -n "${autn[i]}" && "${autn[i]}" == "${autn[j]}" ]]             && why+=("autn")
            [[ "${oct[i]}" == "${oct[j]}" ]]                                  && weak+=("msin_length")
            [[ "${sch[i]}" == "${sch[j]}" ]]                                  && herd+=("scheme")
            [[ "${hnk[i]}" == "${hnk[j]}" ]]                                  && herd+=("hn_public_key_id")
            [[ "${ri[i]}"  == "${ri[j]}"  ]]                                  && herd+=("routing_indicator")

            printf 'pair\t%s\t%s\n' "${lbl[i]}" "${lbl[j]}"
            local w h
            for w in "${why[@]}";  do printf 'identifying\t%s\n' "$w"; done
            for w in "${weak[@]}"; do printf 'weak\t%s\n' "$w"; done
            for h in "${herd[@]}"; do printf 'shared_by_network\t%s\n' "$h"; done
            if (( ${#why[@]} > 0 )); then
                linked=$(( linked + 1 ))
                printf 'verdict\tlinked\n'
                printf 'linked_by\t%s\n' "${why[0]}"
            else
                printf 'verdict\tnot-linked\n'
                if (( ${#weak[@]} > 0 )); then
                    printf 'note\tthe pair shares only %s: the concealed MSIN has the same length, which is a digit count, not an identity\n' \
                        "$(printf '%s,' "${weak[@]}" | sed 's/,$//')"
                else
                    printf 'note\tno identifying field matches: the two observations share nothing but the home network\n'
                fi
            fi
        done
    done
    printf 'pairs\t%s\n' "$pair"
    printf 'linked_pairs\t%s\n' "$linked"

    # Findings: the same three shapes the audit verb reports, but counted over
    # observations instead of a bare SUCI list.
    local e_reuse=0 s_ident=0 av_ident=0 clear=0 k
    for (( k = 0; k < ${#su[@]}; k++ )); do
        (( sch[k] == 0 )) && clear=$(( clear + 1 ))
    done
    e_reuse=$(printf '%s\n' "${eph[@]}" | grep -v '^none$' | sort | uniq -d | grep -c . || true)
    s_ident=$(printf '%s\n' "${su[@]}"  | sort | uniq -d | grep -c . || true)
    av_ident=$(printf '%s\n' "${autn[@]}" | grep -v '^$' | sort | uniq -d | grep -c . || true)
    printf 'reused_ephemeral_keys\t%s\n' "$e_reuse"
    printf 'repeated_sucis\t%s\n'        "$s_ident"
    printf 'repeated_autn\t%s\n'         "$av_ident"
    printf 'cleartext_msin\t%s\n'        "$clear"
    if (( e_reuse > 0 )); then
        printf 'finding\treused-ephemeral-key\n'
        printf 'finding_detail\tan ephemeral public key appears in more than one observation: those rounds are one UE, and the reuse is not what TS 33.501 asks for\n'
    fi
    if (( s_ident > 0 )); then
        printf 'finding\trepeated-suci\n'
        printf 'finding_detail\tthe same SUCI octets appear more than once: the concealment was not refreshed between the rounds\n'
    fi
    if (( av_ident > 0 )); then
        printf 'finding\trepeated-authentication-vector\n'
        printf 'finding_detail\tthe same AUTN reached more than one observation: one vector was reused, so the pair is linkable by the vector itself\n'
    fi
    if (( clear > 0 )); then
        printf 'finding\tcleartext-msin\n'
        printf 'finding_detail\t%s observation(s) use the null scheme: the MSIN is in the clear and nothing is concealed\n' "$clear"
    fi
    if (( linked > 0 )); then
        printf 'verdict\tLINKABLE\n'
    else
        printf 'verdict\tNOT-LINKED\n'
    fi
    return 0
}

# A demonstration with ground truth: the same subscriber's rounds must not
# link, a reused ephemeral key must, and a null-scheme SUCI must. Runs against
# the live home network when a profile exists, so the SUCIs are real output of
# this module's own concealment, not fixtures pasted from somewhere.
suci_link_demo() {
    suci_hn_have || {
        printf 'ERROR\tno home network profile: run --hn-create first\n' >&2; return 1; }
    suci_have_cryptography || {
        printf 'ERROR\t%s\n' "$(suci_missing_dep)" >&2; return 3; }

    local dir="$MOD_TMP/link_demo"
    rm -rf "$dir"; mkdir -p "$dir" 2>/dev/null
    local pub scheme
    pub=$(suci_hn_pget hn_public_key)
    scheme=$(suci_hn_pget scheme)
    [[ -n "$pub" ]] || { printf 'ERROR\tthe profile carries no public key\n' >&2; return 1; }
    [[ -f "$(suci_hn_pget keyfile)" ]] || {
        printf 'ERROR\tthe profile key file is gone: %s\n' \
            "$(suci_sanitize "$(suci_hn_pget keyfile)")" >&2; return 1; }

    local a1 a2 a3 b1 f1 lay hdr
    a1=$(suci_build "$scheme" 0123456789 "$pub" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    lay=$(suci_build "$scheme" 0123456789 "$pub" 001 01 1 0000 | awk -F'\t' '$1=="layout"{print $2}')
    # The reuse case below rebuilds a SUCI with its ephemeral key kept and its
    # ciphertext reversed, so it has to know where the header ends. The header
    # is 5 octets in the compact layout and 8 in the hnid one.
    hdr=10
    [[ "$lay" == "hnid" ]] && hdr=16
    a2=$(suci_build "$scheme" 0123456789 "$pub" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    a3=$(suci_build "$scheme" 0123456789 "$pub" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    b1=$(suci_build "$scheme" 0987654321 "$pub" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    [[ -n "$a1" && -n "$a2" && -n "$a3" && -n "$b1" ]] || {
        printf 'ERROR\tconcealment failed; %s\n' "$(suci_sanitize "$a1")" >&2; return 1; }

    # Same subscriber, three fresh rounds: no shared identifying field.
    printf 'sub-A-round-1\t%s\nsub-A-round-2\t%s\nsub-A-round-3\t%s\nsub-B-round-1\t%s\n' \
        "$a1" "$a2" "$a3" "$b1" > "$dir/fresh.tsv"

    # The threat model the oracle exists for: the UE reuses its ephemeral key.
    # The ciphertext is re-randomised by reversing it, so only the ephemeral
    # key and the scheme output's length survive as shared fields.
    local split=64 head tail reused
    (( scheme == 2 )) && split=66
    head="${a1:0:$(( hdr + split ))}"
    tail="${a1:$(( hdr + split ))}"
    reused="$head$(printf '%s' "$tail" | rev)"
    printf 'sub-A-round-1\t%s\nsub-A-round-2-reused-eph\t%s\n' "$a1" "$reused" > "$dir/reuse.tsv"

    # Null scheme: no concealment at all.
    f1=$(suci_build 0 0123456789 "" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    printf 'sub-A-null-1\t%s\nsub-A-null-2\t%s\n' "$f1" "$f1" > "$dir/null.tsv"

    # Two rounds of the same subscriber that the home network answered with
    # one authentication vector: the AUTN is what gives them away, not the SUCI.
    local auth autn
    auth=$(suci_hn_auth "$a1" 2>/dev/null)
    autn=$(printf '%s\n' "$auth" | awk -F'\t' '$1=="autn"{print $2}')
    if [[ -n "$autn" ]]; then
        printf 'sub-A-autn-1\t%s\t%s\nsub-A-autn-2\t%s\t%s\n' \
            "$a1" "$autn" "$a2" "$autn" > "$dir/same-av.tsv"
    fi

    printf 'demo\t%s\n' "$(suci_sanitize "$dir")"
    local outp
    outp=$(suci_link_oracle "$dir/fresh.tsv")
    printf 'case\tfresh-concealment\n'
    printf 'expected\tNOT-LINKED\n'
    printf 'actual\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')"
    printf 'pairs\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="pairs"{v=$2} END{print v}')"
    printf 'sub-A-round-1\t%s\nsub-B-round-1\t%s\n' "$a1" "$b1" > "$dir/two-subs.tsv"
    outp=$(suci_link_oracle "$dir/two-subs.tsv")
    printf 'case\ttwo-subscribers\n'
    printf 'expected\tNOT-LINKED\n'
    printf 'actual\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')"
    outp=$(suci_link_oracle "$dir/reuse.tsv")
    printf 'case\treused-ephemeral-key\n'
    printf 'expected\tLINKABLE\n'
    printf 'actual\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')"
    printf 'linked_by\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="linked_by"{v=$2} END{print v}')"
    outp=$(suci_link_oracle "$dir/null.tsv")
    printf 'case\tnull-scheme\n'
    printf 'expected\tLINKABLE\n'
    printf 'actual\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')"
    if [[ -n "$autn" ]]; then
        outp=$(suci_link_oracle "$dir/same-av.tsv")
        printf 'case\tsame-authentication-vector\n'
        printf 'expected\tLINKABLE\n'
        printf 'actual\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')"
        printf 'linked_by\t%s\n' "$(printf '%s\n' "$outp" | awk -F'\t' '$1=="linked_by"{v=$2} END{print v}')"
    else
        printf 'case\tsame-authentication-vector\n'
        printf 'expected\tLINKABLE\n'
        printf 'actual\tskipped (no subscriber for %s in the store)\n' "001010123456789"
    fi
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
# The status verb is the honest inventory of this module: what works with no
# key at all, what needs the last hop, and what that last hop is. The optional
# argument probes one key source through the same validation --deconceal uses.
suci_status() {
    local keysrc="${1:-}"
    local py cry
    py=$(suci_have_python && echo "python3 ($(python3 -V 2>&1 | awk '{print $2}'))" || echo missing)
    cry=$(suci_have_cryptography && echo "present ($(python3 -c 'import cryptography; print(cryptography.__version__)' 2>/dev/null))" || echo missing)
    printf 'python3\t%s\n'      "$py"
    printf 'cryptography\t%s\n' "$cry"
    printf 'profile_a\t%s\n'    "$(suci_have_cryptography && echo available || echo unavailable)"
    printf 'profile_b\t%s\n'    "$(suci_have_cryptography && echo available || echo unavailable)"
    printf 'hkdf\t%s\n'         "$(suci_have_python && echo available || echo unavailable)"
    printf 'bcd_codec\tavailable\n'
    printf 'dir\t%s\n'          "$SUCI_DIR"
    printf 'keydir\t%s\n'       "$SUCI_KEYDIR"

    # The home network this host holds, if any: the SIDF key and the PLMN the
    # AUSF answers for. Reported here so a fake cell can ask before it calls.
    if suci_hn_have; then
        printf 'home_network\tconfigured\n'
        printf 'hn_plmn\t%s\n'     "$(suci_hn_plmn)"
        printf 'hn_scheme\t%s\n'   "$(suci_hn_pget scheme)"
        printf 'hn_sn_name\t%s\n'  "$(suci_hn_sn_name)"
        if [[ -f "$(suci_hn_pget keyfile)" ]]; then
            printf 'hn_key_present\tyes\n'
        else
            printf 'hn_key_present\tno\n'
        fi
    else
        printf 'home_network\tnot configured\n'
    fi

    # ── the key interface, as labelled fields ───────────────────────────
    # key_absent is the accurate state when no source defines a key — it is
    # not an error here, because most of this module runs without one.
    #
    # A bare hex scalar does not name its curve, so the same source can be
    # valid for one profile and not the other; probing only profile A would
    # report a perfectly good P-256 key as unusable. Probe both, report the
    # profile the source is actually validated as in `unlocks`, and put the
    # other curve's reading in `unlocks_note` when the source is
    # curve-agnostic. An explicit argument wins over IMSISTING_SUCI_HN_KEY,
    # exactly as it does in --deconceal.
    local src="$keysrc" src_origin="argument"
    if [[ -z "$src" && -n "${IMSISTING_SUCI_HN_KEY:-}" ]]; then
        src="$IMSISTING_SUCI_HN_KEY"; src_origin="env:IMSISTING_SUCI_HN_KEY"
    fi
    if [[ -z "$src" ]]; then
        printf 'key_interface\targument <key-hex|keyfile> | env IMSISTING_SUCI_HN_KEY=<keyfile>\n'
        printf 'key_source\tnone\n'
        printf 'key_state\tkey_absent\n'
        printf 'key_note\tno key supplied: profile A/B deconcealment is unavailable in this state\n'
        printf 'can_without_key\tparse-suci,audit,msin-encode,msin-decode,hkdf,build-suci-conceal\n'
        printf 'cannot_without_key\tdeconceal-profile-a,deconceal-profile-b,msin-recovery\n'
    elif ! suci_have_cryptography >/dev/null 2>&1; then
        printf 'key_interface\targument <key-hex|keyfile> | env IMSISTING_SUCI_HN_KEY=<keyfile>\n'
        printf 'key_source\t%s\n' "$src_origin"
        printf 'key_ref\t%s\n'    "$(suci_sanitize "$src")"
        printf 'key_state\tcrypto_unavailable\n'
        printf 'key_note\tpython3 with the cryptography package is required to validate or use the key\n'
        printf 'can_without_key\tparse-suci,audit\n'
        printf 'cannot_without_key\tdeconceal-profile-a,deconceal-profile-b,msin-recovery\n'
    else
        local prof rc_a=0 rc_b=0 out_a out_b
        out_a=$(suci_key_resolve "$src" 1 2>/dev/null) || rc_a=$?
        out_b=$(suci_key_resolve "$src" 2 2>/dev/null) || rc_b=$?
        local curve enc pub
        curve=$(printf '%s\n' "$out_a$out_b" | awk -F'\t' '$1=="curve"{print $2; exit}')
        enc=$(printf '%s\n'   "$out_a$out_b" | awk -F'\t' '$1=="encoding"{print $2; exit}')
        pub=$(printf '%s\n'   "$out_a$out_b" | awk -F'\t' '$1=="public_key"{print $2; exit}')
        printf 'key_interface\targument <key-hex|keyfile> | env IMSISTING_SUCI_HN_KEY=<keyfile>\n'
        printf 'key_source\t%s\n' "$src_origin"
        printf 'key_ref\t%s\n'    "$(suci_sanitize "$src")"
        # The most specific complaint wins; a key that works for at least one
        # profile is validated for that profile.
        if (( rc_a == 0 || rc_b == 0 )); then
            # `unlocks` names the profile this source is actually VALIDATED as,
            # not every profile its bytes could be read on. A curve-agnostic
            # source -- bare hex, a bare hex file, or a --genkey TSV, none of
            # which bind the octets to a curve -- is read as X25519 when the
            # profile is A, so that is the one profile it is validated as.
            # Saying "unlocks profile-a,profile-b" read as a capability claim
            # the octets do not carry: the secp256r1 reading is a DIFFERENT key
            # with a different public key, and it deconceals only traffic
            # concealed under that other public key. The second reading is
            # spelled out in its own unlocks_note row instead of being folded
            # into the capability row. A container that names its curve has no
            # second reading, so it gets no note.
            local unlocked note_suffix="" curve_agnostic=0
            case "$enc" in raw-hex|hex-file|tsv-hex) curve_agnostic=1 ;; esac
            if (( rc_a == 0 )); then unlocked="profile-a"; else unlocked="profile-b"; fi
            printf 'key_state\tkey_validated\n'
            printf 'key_curve\t%s\n'      "$curve"
            printf 'key_encoding\t%s\n'   "$enc"
            printf 'hn_public_key\t%s\n'  "$pub"
            printf 'unlocks\t%s\n'        "$unlocked"
            if (( curve_agnostic == 1 )); then
                local pub_a pub_b note
                pub_a=$(printf '%s\n' "$out_a" | awk -F'\t' '$1=="public_key"{print $2; exit}')
                pub_b=$(printf '%s\n' "$out_b" | awk -F'\t' '$1=="public_key"{print $2; exit}')
                if [[ -n "$pub_a" && -n "$pub_b" ]]; then
                    note="curve-agnostic 32-octet scalar, not bound to a curve: profile A reads these octets as X25519 (public key $pub_a) and profile B reads the same octets as secp256r1 (public key $pub_b); those are two different keys, so the octets deconceal profile-a traffic only if they are the intended X25519 key, and profile-b traffic only if they are the intended secp256r1 key"
                else
                    note="curve-agnostic 32-octet scalar, not bound to a curve: the octets are not readable as a secp256r1 private scalar, so only the validated reading -- $unlocked -- applies"
                fi
                printf 'unlocks_note\t%s\n' "$(suci_sanitize "$note")"
                note_suffix=" (see unlocks_note: the other profile reads the same octets as a different key)"
            fi
            printf 'key_note\tkey validated; deconcealment is available for %s%s\n' "$unlocked" "$note_suffix"
            printf 'can_without_key\tparse-suci,audit,msin-encode,msin-decode,hkdf,build-suci-conceal\n'
            printf 'cannot_without_key\tmsin-recovery-without-this-key\n'
        else
            local rc="$rc_a"
            (( rc_a == 4 && rc_b != 4 )) && rc=4
            case "$rc" in
                2) printf 'key_state\tkey_missing\n'
                   printf 'key_note\tno key supplied: set IMSISTING_SUCI_HN_KEY or pass a key path\n' ;;
                3) printf 'key_state\tkey_unreadable\n'
                   printf 'key_note\tthe path exists but cannot be opened as a regular file by this user\n' ;;
                4) printf 'key_state\tkey_wrong_curve\n'
                   printf 'key_note\tthe key is valid but on the wrong curve for both profiles (profile A: X25519, profile B: secp256r1)\n' ;;
                *) printf 'key_state\tkey_malformed\n'
                   printf 'key_note\tthe key material could not be parsed as a private key\n' ;;
            esac
            printf 'can_without_key\tparse-suci,audit\n'
            printf 'cannot_without_key\tdeconceal-profile-a,deconceal-profile-b,msin-recovery\n'
        fi
    fi
    printf 'last_hop\thome-network-private-key\n'
    printf 'last_hop_detail\t%s\n' \
        "the private key matching the home network public key that concealed the SUPI (profile A: X25519, profile B: secp256r1) -- held by the operator or extracted from it"
    return 0
}

suci_cli_status_tsv() { suci_status "${1:-}"; }

# Report what one key source resolves to, through the same interface
# --deconceal uses. Non-zero on refusal, so a script can gate on it.
suci_cmd_verify_hnkey() {
    local src="${1:-}" profile="${2:-1}"
    [[ "$profile" =~ ^[12]$ ]] || {
        printf 'ERROR\tprofile must be 1 (X25519) or 2 (secp256r1)\n' >&2; return 2; }
    [[ -n "$src" || -n "${IMSISTING_SUCI_HN_KEY:-}" ]] || {
        printf 'ERROR\tusage: --verify-hnkey <key-hex|keyfile> [profile] (or set IMSISTING_SUCI_HN_KEY)\n' >&2
        printf 'key_state\tkey_missing\n'
        printf 'key_note\tno key supplied: pass a key or set IMSISTING_SUCI_HN_KEY\n'
        return 2; }
    # An omitted source still resolves through IMSISTING_SUCI_HN_KEY: the
    # interface has exactly one fallback and it is that variable, so this
    # verb must be able to report on it too.
    local out rc=0
    out=$(suci_key_resolve "$src" "$profile") || rc=$?
    if (( rc != 0 )); then
        printf 'key_state\t%s\n' "$(case "$rc" in 2) echo key_missing;; 3) echo key_unreadable;; 4) echo key_wrong_curve;; 1) echo key_malformed;; *) echo refused;; esac)"
        printf 'key_note\t%s\n' "$(case "$rc" in
            2) echo 'no key supplied: pass a key or set IMSISTING_SUCI_HN_KEY';;
            3) echo 'the path exists but is not a readable regular file';;
            4) echo 'the key is valid but on the wrong curve for this profile';;
            *) echo 'the key material could not be parsed as a private key';; esac)"
        return "$rc"
    fi
    printf '%s\n' "$out"
    printf 'key_state\tkey_validated\n'
}

suci_cmd_build() {
    local scheme="${1:-1}" msin="${2:-}" hn_pub="${3:-}" mcc="${4:-001}" mnc="${5:-01}"
    local hnkey="${6:-1}" ri="${7:-0000}" layout="${8:-hnid}"
    if [[ -z "$msin" ]]; then
        [[ -n "${IMSISTING_CLI:-}" ]] && { printf 'ERROR\tusage: --build-suci <0|1|2> <msin> [hn-pubkey-hex] [mcc] [mnc] [hn-key-id] [routing-ind] [hnid|compact]\n' >&2; return 2; }
        printf 'ERROR\tusage: --build-suci <0|1|2> <msin> [hn-pubkey-hex] [mcc] [mnc] [hn-key-id] [routing-ind] [hnid|compact]\n' >&2; return 2
    fi
    suci_build "$scheme" "$msin" "$hn_pub" "$mcc" "$mnc" "$hnkey" "$ri" "$layout"
}

suci_cmd_parse() {
    local hex="${1:-}" layout="${2:-auto}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --parse-suci <hex> [hnid|compact|auto]\n' >&2; return 2; }
    suci_parse "$hex" "$layout"
}

suci_cmd_deconceal() {
    local hex="${1:-}" key="${2:-}"
    [[ -n "$hex" ]] || {
        printf 'ERROR\tusage: --deconceal <suci-hex> <key-hex|keyfile>  (or set IMSISTING_SUCI_HN_KEY=<keyfile>)\n' >&2; return 2; }
    if [[ -z "$key" && -z "${IMSISTING_SUCI_HN_KEY:-}" ]]; then
        printf 'ERROR\tusage: --deconceal <suci-hex> <key-hex|keyfile>  (or set IMSISTING_SUCI_HN_KEY=<keyfile>)\n' >&2
        return 2
    fi
    suci_deconceal "$hex" "$key"
}

suci_cmd_hkdf() {
    local ikm="${1:-}" salt="${2:-}" info="${3:-}" len="${4:-32}"
    [[ -n "$ikm" ]] || { printf 'ERROR\tusage: --hkdf <ikm-hex> <salt-hex|-> <info> [len]\n' >&2; return 2; }
    [[ "$salt" == "-" ]] && salt=""
    suci_hkdf "$ikm" "$salt" "$info" "$len"
}

suci_cmd_msin_encode() {
    local msin="${1:-}"
    [[ -n "$msin" ]] || { printf 'ERROR\tusage: --msin-encode <digits>\n' >&2; return 2; }
    local out rc=0
    out=$(suci_msin_encode "$msin") || rc=$?
    (( rc == 0 )) || return "$rc"
    printf 'msin\t%s\nbcd\t%s\noctets\t%s\n' "$(suci_sanitize "$msin")" "$out" "$(( ${#out} / 2 ))"
}

suci_cmd_msin_decode() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --msin-decode <bcd-hex>\n' >&2; return 2; }
    local out rc=0
    out=$(suci_msin_decode "$hex") || rc=$?
    (( rc == 0 )) || return "$rc"
    printf 'bcd\t%s\nmsin\t%s\ndigits\t%s\n' "$hex" "$out" "${#out}"
}

suci_cmd_audit() { suci_audit "${1:-}"; }

suci_cmd_genkey() {
    local scheme="${1:-1}" out="${2:-}"
    local res rc=0
    res=$(suci_gen_keypair "$scheme") || rc=$?
    (( rc == 0 )) || return "$rc"
    printf '%s\n' "$res"
    if [[ -n "$out" ]]; then
        mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }
        if ! { printf '# SUCI home network key pair, scheme %s\n# generated by 14_suci.sh\n' "$scheme"
               printf '%s\n' "$res"; } > "$out"; then
            printf 'ERROR\tcannot write %s\n' "$out" >&2
            return 1
        fi
        # The private key is a secret: keep it owner-only.
        chmod 600 "$out" 2>/dev/null
        printf 'keyfile\t%s\n' "$out"
    fi
}

# ── the home network: SIDF and AUSF ─────────────────────────────────────
# R2 of the queue. The two functions that make a SUCI mean something again
# live together here because they are one deployment: the SIDF holds the
# concealment private key and turns an arriving SUCI back into a SUPI, and the
# AUSF holds (or reaches) the subscriber's K and answers the serving network's
# authentication request. On real network functions these are two hosts; here
# they are two verbs and one profile.
#
# Profile on disk: $STATE_DIR/suci_hn/profile.tsv (0600), directory 0700. The
# private key is its own file (0600) and no verb here ever prints it.
#
# What is NOT done here, by name: no Nudm/Nausf HTTP, no SBI, no AUSF service
# operation. This is the cryptography and the state those services carry, so a
# test UE or a fake cell (R4) can be authenticated locally.

suci_hn_dir()     { printf '%s/suci_hn' "${STATE_DIR:-$IMSISTING_ROOT/state}"; }
suci_hn_profile() { printf '%s/profile.tsv' "$(suci_hn_dir)"; }
suci_hn_keyfile() { printf '%s/hn_priv.key' "$(suci_hn_dir)"; }

# One row from the profile. Reads, never writes.
suci_hn_pget() { # <key>
    local f
    f=$(suci_hn_profile)
    [[ -f "$f" ]] || return 0
    awk -F'\t' -v k="$1" '!/^#/ && $1 == k { print $2; exit }' "$f"
}

suci_hn_have() { [[ -f "$(suci_hn_profile)" ]]; }

suci_hn_ensure_dir() {
    local d
    d=$(suci_hn_dir)
    if [[ ! -d "$d" ]]; then
        mkdir -p "$d" 2>/dev/null || {
            printf 'ERROR\tcannot create %s\n' "$(suci_sanitize "$d")" >&2; return 1; }
        chmod 700 "$d" 2>/dev/null
    fi
    return 0
}

suci_hn_plmn() { printf '%s%s' "$(suci_hn_pget mcc)" "$(suci_hn_pget mnc)"; }

# The serving network name, TS 24.501 §4.4.1: the MNC is always three digits
# here, so a two-digit MNC is zero-padded. This string is a KDF input, not a
# label: a wrong form produces keys no core accepts.
suci_hn_sn_name() {
    local mcc mnc
    mcc=$(suci_hn_pget mcc)
    mnc=$(suci_hn_pget mnc)
    [[ -n "$mcc" && -n "$mnc" ]] || return 0
    printf '5G:mnc%03d.mcc%s.3gppnetwork.org' "$((10#$mnc))" "$mcc"
}

# A hex string's UTF-8 bytes, which is what the KDF wants.
suci_hn_sn_hex() {
    local name
    name=$(suci_hn_sn_name)
    [[ -n "$name" ]] || return 0
    printf '%s' "$name" | od -An -tx1 | tr -d ' \n'
}

# Is this IMSI known to the key store? Answers by asking 16_sim, so the store
# format stays that module's business.
suci_hn_store_row() { # <imsi> -> "ki_masked=<v>" or empty
    local mod out
    mod="$IMSISTING_ROOT/modules/16_sim.sh"
    [[ -f "$mod" ]] || return 0
    out=$( bash "$mod" --key-show --imsi "$1" 2>/dev/null ) || return 0
    awk -F'\t' '$1 == "ki_masked" { print $2; exit }' <<< "$out"
}

# One named 5G derivation through the crypto tool. The truncation and the
# CK||IK key live there; this function only carries arguments.
suci_hn_derive() { # <res-star|hxres|kseaf> [k=v ...]
    local kind="$1"; shift
    local tool out rc=0
    tool="$IMSISTING_ROOT/tools/gsm_crypto.py"
    [[ -f "$tool" ]] || { printf 'ERROR\tno %s\n' "$tool" >&2; return 1; }
    out=$(python3 "$tool" --derive "$kind" "$@" 2>/dev/null) || rc=$?
    (( rc == 0 )) || { printf 'ERROR\t%s derivation refused its inputs\n' "$kind" >&2; return 1; }
    case "$kind" in
        res-star) awk -F'\t' '$1 == "res_star"  { print $2; exit }' <<< "$out" ;;
        hxres)    awk -F'\t' '$1 == "hxres_star"{ print $2; exit }' <<< "$out" ;;
        kseaf)    awk -F'\t' '$1 == "kseaf"     { print $2; exit }' <<< "$out" ;;
        *) return 1 ;;
    esac
}

# ── the profile ─────────────────────────────────────────────────────────
suci_hn_create() {
    local mcc=001 mnc=01 mnc_digits=2 scheme=1 ri=0000 keyfile='' force=0
    while (( $# )); do
        case "$1" in
            --mcc)        mcc="${2:-}";        shift 2 2>/dev/null || shift ;;
            --mnc)        mnc="${2:-}";        shift 2 2>/dev/null || shift ;;
            --mnc-digits) mnc_digits="${2:-}"; shift 2 2>/dev/null || shift ;;
            --scheme)     scheme="${2:-}";     shift 2 2>/dev/null || shift ;;
            --ri)         ri="${2:-}";         shift 2 2>/dev/null || shift ;;
            --keyfile)    keyfile="${2:-}";    shift 2 2>/dev/null || shift ;;
            --force)      force=1;             shift ;;
            *)            shift ;;
        esac
    done

    [[ "$mcc" =~ ^[0-9]{3}$ ]] || {
        printf 'ERROR\t--mcc must be exactly three digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{1,3}$ ]] || {
        printf 'ERROR\t--mnc must be one to three digits\n' >&2; return 2; }
    (( mnc_digits == 2 || mnc_digits == 3 )) || {
        printf 'ERROR\t--mnc-digits must be 2 or 3 (it decides where the MSIN starts)\n' >&2; return 2; }
    (( ${#mnc} == mnc_digits )) || {
        printf 'ERROR\t--mnc %s is %d digit(s) but --mnc-digits says %d\n' \
               "$mnc" "${#mnc}" "$mnc_digits" >&2; return 2; }
    [[ "$scheme" =~ ^[12]$ ]] || {
        printf 'ERROR\t--scheme must be 1 (profile A, X25519) or 2 (profile B, secp256r1)\n' >&2; return 2; }
    [[ "$ri" =~ ^[0-9]{1,4}$ ]] || {
        printf 'ERROR\t--ri must be one to four decimal digits\n' >&2; return 2; }

    local f
    f=$(suci_hn_profile)
    if [[ -f "$f" ]] && (( force == 0 )); then
        printf 'ERROR\ta home network profile already exists: %s (--force replaces it)\n' \
               "$(suci_sanitize "$f")" >&2
        return 1
    fi

    local dep
    dep=$(suci_missing_dep)
    local kf
    kf=$(suci_hn_keyfile)
    if [[ -n "$keyfile" ]]; then
        [[ -f "$keyfile" ]] || {
            printf 'ERROR\tno such key file: %s\n' "$(suci_sanitize "$keyfile")" >&2; return 1; }
        kf="$keyfile"
    else
        if [[ -n "$dep" ]]; then
            printf 'ERROR\t%s is required to generate the concealment key pair\n' "$dep" >&2
            return 1
        fi
        local kout
        kout=$(suci_gen_keypair "$scheme") || return 1
        suci_hn_ensure_dir || return 1
        # umask, not a later chmod: the scalar is never briefly readable.
        ( umask 077; printf '%s\n' "$kout" > "$(suci_hn_keyfile)" ) || {
            printf 'ERROR\tcannot write %s\n' "$(suci_sanitize "$(suci_hn_keyfile)")" >&2
            return 1; }
        chmod 600 "$(suci_hn_keyfile)" 2>/dev/null
    fi

    # Validate the key against the profile's curve before the profile is
    # written: a profile pointing at a key that cannot deconceal anything is
    # worse than no profile.
    local kres pub
    kres=$(suci_key_resolve "$kf" "$scheme") || return 1
    pub=$(awk -F'\t' '$1 == "public_key" { print $2; exit }' <<< "$kres")
    [[ -n "$pub" ]] || {
        printf 'ERROR\tthe key resolved to no public key\n' >&2; return 1; }

    local sn_name
    sn_name=$(printf '5G:mnc%03d.mcc%s.3gppnetwork.org' "$((10#$mnc))" "$mcc")
    local tmp
    tmp="$f.tmp.$$"
    suci_hn_ensure_dir || return 1
    ( umask 077; {
        printf '# SUCI home network profile (SIDF + AUSF)\n'
        printf 'mcc\t%s\n' "$mcc"
        printf 'mnc\t%s\n' "$mnc"
        printf 'mnc_digits\t%s\n' "$mnc_digits"
        printf 'plmn\t%s%s\n' "$mcc" "$mnc"
        printf 'ri\t%s\n' "$ri"
        printf 'scheme\t%s\n' "$scheme"
        printf 'hn_public_key\t%s\n' "$pub"
        printf 'keyfile\t%s\n' "$(suci_sanitize "$kf")"
        printf 'sn_name\t%s\n' "$sn_name"
        printf 'created\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      } > "$tmp" ) || {
        printf 'ERROR\tcannot write %s\n' "$(suci_sanitize "$f")" >&2; return 1; }
    mv -f "$tmp" "$f" || { rm -f "$tmp"; return 1; }
    chmod 600 "$f" 2>/dev/null

    printf 'profile\t%s\n' "$(suci_sanitize "$f")"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'mnc_digits\t%s\n' "$mnc_digits"
    printf 'plmn\t%s%s\n' "$mcc" "$mnc"
    printf 'ri\t%s\n' "$ri"
    printf 'scheme\t%s\n' "$scheme"
    printf 'curve\t%s\n' "$([[ "$scheme" == 1 ]] && echo X25519 || echo secp256r1)"
    printf 'hn_public_key\t%s\n' "$pub"
    printf 'keyfile\t%s\n' "$(suci_sanitize "$kf")"
    printf 'sn_name\t%s\n' "$sn_name"
    printf 'mode\t600\n'
    printf 'role\t%s\n' "SIDF holds the private key; AUSF reaches the K store for the vector"
    return 0
}

suci_hn_show() {
    suci_hn_have || {
        printf 'ERROR\tno home network profile: run --hn-create first\n' >&2; return 1; }
    local k kf
    kf=$(suci_hn_pget keyfile)
    printf 'profile\t%s\n' "$(suci_sanitize "$(suci_hn_profile)")"
    for k in mcc mnc mnc_digits plmn ri scheme hn_public_key sn_name created; do
        printf '%s\t%s\n' "$k" "$(suci_hn_pget "$k")"
    done
    printf 'keyfile\t%s\n' "$(suci_sanitize "$kf")"
    if [[ -f "$kf" ]]; then
        printf 'key_present\tyes\n'
    else
        printf 'key_present\tno\n'
        printf 'note\tthe profile points at a key file that is not there: deconcealment will refuse\n'
    fi
}

# ── SIDF: a SUCI in, a SUPI out ─────────────────────────────────────────
suci_hn_deconceal() { # <suci-hex>
    local suci="${1:-}"
    [[ -n "$suci" ]] || {
        printf 'ERROR\tusage: --hn-deconceal <suci-hex>\n' >&2; return 2; }
    suci_hn_have || {
        printf 'ERROR\tno home network profile: run --hn-create first\n' >&2; return 1; }
    local kf
    kf=$(suci_hn_pget keyfile)
    [[ -f "$kf" ]] || {
        printf 'ERROR\tthe profile key file is missing: %s\n' "$(suci_sanitize "$kf")" >&2
        return 1; }

    local out
    out=$(suci_deconceal "$suci" "$kf") || return 1
    local msin
    msin=$(awk -F'\t' '$1 == "msin" { print $2; exit }' <<< "$out")
    [[ -n "$msin" ]] || {
        printf 'ERROR\tdeconcealment returned no MSIN\n' >&2; return 1; }

    local mcc mnc mnc_digits imsi
    mcc=$(suci_hn_pget mcc); mnc=$(suci_hn_pget mnc); mnc_digits=$(suci_hn_pget mnc_digits)
    imsi="$mcc$mnc$msin"
    local want=$(( 15 - 3 - mnc_digits ))
    if (( ${#msin} != want )); then
        printf 'note\tMSIN is %d digits; this PLMN with a %d-digit MNC expects %d, so the IMSI is %d digits\n' \
               "${#msin}" "$mnc_digits" "$want" "$(( 3 + mnc_digits + ${#msin} ))"
    fi
    local known
    known=$(suci_hn_store_row "$imsi")

    printf 'role\tSIDF\n'
    printf 'scheme\t%s\n' "$(awk -F'\t' '$1 == "scheme" { print $2; exit }' <<< "$out")"
    printf 'hn_public_key\t%s\n' "$(awk -F'\t' '$1 == "hn_public_key" { print $2; exit }' <<< "$out")"
    printf 'msin\t%s\n' "$msin"
    printf 'imsi\t%s\n' "$imsi"
    printf 'supi\timsi-%s\n' "$imsi"
    if [[ -n "$known" ]]; then
        printf 'store\thit\n'
        printf 'store_ki\t%s\n' "$known"
    else
        printf 'store\tmiss\n'
        printf 'note\tthe de-concealed IMSI has no row in the key store, so no AUSF vector can be made for it\n'
    fi
    return 0
}

# ── AUSF: the vector the serving network asked for ──────────────────────
# Resolve the SUCI, take the subscriber's K from the store, run one 5G-AKA
# event and hand back exactly the values the SEAF and the UE need:
# RAND || AUTN towards the UE, XRES* and HXRES* towards the SEAF, KSEAF up.
suci_hn_auth() { # <suci-hex> [rand-hex]
    local suci="${1:-}" rand="${2:-}"
    [[ -n "$suci" ]] || {
        printf 'ERROR\tusage: --hn-auth <suci-hex> [rand-hex]\n' >&2; return 2; }
    suci_hn_have || {
        printf 'ERROR\tno home network profile: run --hn-create first\n' >&2; return 1; }

    local sid
    sid=$(suci_hn_deconceal "$suci") || return 1
    local imsi store
    imsi=$(awk -F'\t' '$1 == "imsi" { print $2; exit }' <<< "$sid")
    store=$(awk -F'\t' '$1 == "store" { print $2; exit }' <<< "$sid")
    [[ -n "$imsi" ]] || { printf 'ERROR\tno IMSI came out of the SIDF step\n' >&2; return 1; }
    [[ "$store" == hit ]] || {
        printf 'ERROR\t%s de-concealed to an IMSI the key store does not hold\n' "$imsi" >&2
        printf 'ERROR\tstore a subscriber for it with: modules/16_sim.sh --key-add --imsi %s ...\n' "$imsi" >&2
        return 1; }

    local sn sn_hex
    sn=$(suci_hn_sn_name)
    sn_hex=$(suci_hn_sn_hex)
    [[ -n "$sn" && -n "$sn_hex" ]] || {
        printf 'ERROR\tthe profile carries no SN name\n' >&2; return 1; }

    if [[ -z "$rand" ]]; then
        rand=$(openssl rand -hex 16 2>/dev/null) || {
            printf 'ERROR\tcould not draw a RAND (openssl rand)\n' >&2; return 1; }
        rand=${rand^^}
    fi
    [[ "$rand" =~ ^[0-9a-fA-F]{32}$ ]] || {
        printf 'ERROR\tRAND must be 32 hex digits\n' >&2; return 2; }

    local mod out
    mod="$IMSISTING_ROOT/modules/16_sim.sh"
    [[ -f "$mod" ]] || { printf 'ERROR\tno %s\n' "$mod" >&2; return 1; }
    out=$( bash "$mod" --aka-responder --imsi "$imsi" --rand "$rand" \
                  --5g --sn-name "$sn" 2>&1 ) || {
        printf 'ERROR\tthe AKA responder refused the request\n' >&2
        [[ -n "$out" ]] && sed -n '1,4p' <<< "$out" >&2
        return 1; }

    local xres autn ck ik sqn kausf res_star
    xres=$(awk -F'\t' '$1 == "xres" { print $2; exit }' <<< "$out")
    autn=$(awk -F'\t' '$1 == "autn" { print $2; exit }' <<< "$out")
    ck=$(awk -F'\t' '$1 == "ck" { print $2; exit }' <<< "$out")
    ik=$(awk -F'\t' '$1 == "ik" { print $2; exit }' <<< "$out")
    sqn=$(awk -F'\t' '$1 == "sqn" { print $2; exit }' <<< "$out")
    kausf=$(awk -F'\t' '$1 == "kausf" { print $2; exit }' <<< "$out")
    res_star=$(awk -F'\t' '$1 == "res_star" { print $2; exit }' <<< "$out")
    [[ -n "$xres" && -n "$autn" && -n "$ck" && -n "$ik" && -n "$kausf" && -n "$res_star" ]] || {
        printf 'ERROR\tthe responder made an incomplete vector\n' >&2; return 1; }

    # The AUSF's own two values, derived here from XRES and never copied from
    # the responder's RES* row: XRES* is XRES through the same clause, and the
    # equality is the check that the two halves agree.
    local xres_star hxres_star kseaf matches=no
    xres_star=$(suci_hn_derive res-star --ck "$ck" --ik "$ik" --sn "$sn_hex" \
                    --rand "$rand" --res "$xres") || return 1
    [[ "$xres_star" == "$res_star" ]] && matches=yes
    hxres_star=$(suci_hn_derive hxres --rand "$rand" --xres-star "$xres_star") || return 1
    kseaf=$(suci_hn_derive kseaf --key "$kausf" --sn "$sn_hex") || return 1

    printf 'role\tAUSF\n'
    printf 'auth_type\t5G-AKA\n'
    printf 'supi\timsi-%s\n' "$imsi"
    printf 'serving_network\t%s\n' "$sn"
    printf 'rand\t%s\n' "$rand"
    printf 'autn\t%s\n' "$autn"
    printf 'sqn\t%s\n' "$sqn"
    printf 'xres_star\t%s\n' "$xres_star"
    printf 'hxres_star\t%s\n' "$hxres_star"
    printf 'kausf\t%s\n' "$kausf"
    printf 'kseaf\t%s\n' "$kseaf"
    printf 'xres_star_matches\t%s\n' "$matches"
    printf 'source\tTS 33.501 A.4 / A.5 / A.6; the KDF key is CK||IK and XRES* is the rightmost 128 of 256 bits\n'
    printf 'note\tthe card side of the proof needs the physical USIM: RES* comes from the same clause on RES\n'
    printf 'note\tnot built here: KAMF (the SEAF/AMF derivation with ABBA) and the Nausf service itself\n'
    return 0
}

# ── the resident home network ───────────────────────────────────────────
# A line protocol on stdin so a fake cell or a test UE can drive one process
# instead of a shell call per message. AUTH on the same SUCI returns a fresh
# vector: the SQN counter lives in the key store, so two requests never share
# one sequence number.
suci_hn_serve() {
    suci_hn_have || {
        printf 'ERROR\tno home network profile: run --hn-create first\n' >&2; return 1; }
    local line verb arg rc
    printf 'served\tready\n'
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "${line//[[:space:]]/}" ]] && continue
        verb="${line%%[[:space:]]*}"
        arg="${line#"$verb"}"
        arg="${arg#"${arg%%[![:space:]]*}"}"
        case "${verb^^}" in
            SUCI)
                if [[ -z "$arg" ]]; then
                    printf 'served\tsuci\tneed\tone SUCI in hex\n'; continue
                fi
                rc=0
                suci_hn_deconceal "$arg" || rc=$?
                printf 'served\tsuci\trc\t%d\n' "$rc"
                ;;
            AUTH)
                if [[ -z "$arg" ]]; then
                    printf 'served\tauth\tneed\tone SUCI in hex\n'; continue
                fi
                rc=0
                suci_hn_auth $arg || rc=$?
                printf 'served\tauth\trc\t%d\n' "$rc"
                ;;
            SHOW)
                suci_hn_show
                printf 'served\tshow\tok\n'
                ;;
            QUIT|EXIT)
                printf 'served\tbye\n'
                return 0
                ;;
            *)
                printf 'served\tunknown\t%s\n' "$verb"
                ;;
        esac
        printf 'served\tawaiting\n'
    done
    return 0
}

# ── selftest — no radio, no root, no network ────────────────────────────
suci_selftest() {
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
    export TMP_DIR="$d/tmp" SUCI_DIR="$d/loot/suci" SUCI_KEYDIR="$d/loot/suci/keys"
    mkdir -p "$SUCI_DIR" "$SUCI_KEYDIR"

    # 1. BCD MSIN codec, even and odd digit counts (TS 23.003 §2.2).
    #    10 digits -> 5 octets, nibble-swapped: "1234567890" -> 21 43 65 87 09
    chk bcd-enc-10   "$(suci_msin_encode 1234567890)" "2143658709"
    chk bcd-enc-5    "$(suci_msin_encode 12345)"      "2143f5"
    chk bcd-enc-1    "$(suci_msin_encode 7)"          "f7"
    chk bcd-enc-2    "$(suci_msin_encode 12)"         "21"
    chk bcd-enc-9    "$(suci_msin_encode 123456789)"  "21436587f9"
    # Round trip both parities.
    chk bcd-rt-10    "$(suci_msin_decode "$(suci_msin_encode 1234567890)")" "1234567890"
    chk bcd-rt-9     "$(suci_msin_decode "$(suci_msin_encode 123456789)")"  "123456789"
    chk bcd-rt-1     "$(suci_msin_decode "$(suci_msin_encode 0)")"          "0"
    chk bcd-rt-15    "$(suci_msin_decode "$(suci_msin_encode 123456789012345)")" "123456789012345"
    chk bcd-dec-odd  "$(suci_msin_decode 2143f5)"     "12345"
    chk bcd-dec-fill "$(suci_msin_decode f7)"         "7"
    # The filler must only be legal as the final high nibble.
    chk bcd-fill-mid "$(suci_msin_decode f123 >/dev/null 2>&1; echo $?)" "1"
    chk bcd-nondigit "$(suci_msin_decode a1 >/dev/null 2>&1; echo $?)"  "1"
    chk bcd-odd-hex  "$(suci_msin_decode abc >/dev/null 2>&1; echo $?)" "2"
    chk bcd-empty    "$(suci_msin_encode '' >/dev/null 2>&1; echo $?)"  "2"
    chk bcd-alpha    "$(suci_msin_encode 12ab >/dev/null 2>&1; echo $?)" "2"
    chk bcd-21dig    "$(suci_msin_encode 123456789012345678901 >/dev/null 2>&1; echo $?)" "2"

    # 2. HKDF-SHA256 against the RFC 5869 Appendix A vectors. All three
    #    SHA-256 cases, byte-exact, including the PRK.
    if suci_have_python; then
        # Test Case 1: IKM 22x0b, salt 000102..0c, info f0f1..f9, L=42
        out=$(suci_hkdf "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" \
                        "000102030405060708090a0b0c" "f0f1f2f3f4f5f6f7f8f9" 42)
        chk hkdf-1-prk "$(fld "$out" prk)" "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        chk hkdf-1-okm "$(fld "$out" okm)" "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        chk hkdf-1-len "$(printf '%s' "$(fld "$out" okm)" | wc -c)" "84"
        chk hkdf-1-n   "$(fld "$out" n)" "2"

        # Test Case 2: 80-octet IKM/salt/info, L=82.
        local ikm2 salt2 info2
        ikm2=$(python3 -c "print(''.join('%02x'%i for i in range(0x00,0x50)))")
        salt2=$(python3 -c "print(''.join('%02x'%i for i in range(0x60,0xb0)))")
        info2=$(python3 -c "print(''.join('%02x'%i for i in range(0xb0,0x100)))")
        out=$(suci_hkdf "$ikm2" "$salt2" "$info2" 82)
        chk hkdf-2-prk "$(fld "$out" prk)" "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        chk hkdf-2-okm "$(fld "$out" okm)" "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        chk hkdf-2-len "$(printf '%s' "$(fld "$out" okm)" | wc -c)" "164"

        # Test Case 3: zero-length salt and info, L=42.
        out=$(suci_hkdf "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" "" "" 42)
        chk hkdf-3-prk "$(fld "$out" prk)" "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        chk hkdf-3-okm "$(fld "$out" okm)" "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

        # Extract and expand are separately inspectable: PRK is
        # HMAC-SHA-256(salt, IKM), which openssl can reproduce.
        if command -v openssl >/dev/null 2>&1; then
            local want_prk
            want_prk=$(printf '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b' | xxd -r -p | \
                       openssl dgst -sha256 -mac HMAC -macopt hexkey:000102030405060708090a0b0c -binary | xxd -p | tr -d '\n')
            chk hkdf-1-prk-openssl "$(fld "$(suci_hkdf "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" "000102030405060708090a0b0c" "f0f1f2f3f4f5f6f7f8f9" 42)" prk)" "$want_prk"
        else
            printf 'hkdf-openssl-crosscheck\tSKIP openssl not installed\n'
        fi
        chk hkdf-badlen "$(suci_hkdf 0b0b 00 "" 99999 >/dev/null 2>&1; echo $?)" "2"
        chk hkdf-badikm "$(suci_hkdf zz 00 "" 32 >/dev/null 2>&1; echo $?)"    "2"
        chk hkdf-badsalt "$(suci_hkdf 0b0b zz "" 32 >/dev/null 2>&1; echo $?)" "2"
        chk hkdf-hashlen "$(fld "$(suci_hkdf 0b0b "" "" 32)" hash_len)" "32"
    else
        printf 'hkdf-rfc5869\tSKIP python3 not installed\n'
    fi

    # 3. SUCI structure parse with the real field offsets.
    #    Built by hand: b0 = 0x08 (SUPI format 0 = IMSI, identity 1 = SUCI),
    #    hn key id 0x01, scheme octet 0x11 (scheme id 1 = profile A in the
    #    low nibble), routing indicator "0001" -> BCD 00 01, then 32 bytes of
    #    ephemeral key and 8 bytes of ciphertext.
    local epk="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    local ct="0011223344556677"
    out=$(suci_parse "0801000101${epk}${ct}")
    chk suci-supi-type "$(fld "$out" supi_type)"        "0"
    chk suci-supi-name "$(fld "$out" supi_type_name)"   "IMSI"
    chk suci-hnkey     "$(fld "$out" hn_public_key_id)" "1"
    chk suci-scheme    "$(fld "$out" protection_scheme)" "1"
    chk suci-scheme-n  "$(fld "$out" scheme_name)"      "ECIES profile A (X25519)"
    chk suci-ri        "$(fld "$out" routing_indicator)" "0001"
    chk suci-epk       "$(fld "$out" ephemeral_public_key)" "$epk"
    chk suci-ct        "$(fld "$out" ciphertext)"       "$ct"
    chk suci-exposed   "$(fld "$out" msin_exposed)"     "no"
    # Null scheme: the MSIN is the scheme output, in the clear.
    out=$(suci_parse "08010000002143658709")
    chk suci-null-scheme "$(fld "$out" protection_scheme)" "0"
    chk suci-null-name   "$(fld "$out" scheme_name)" "null-scheme (MSIN in the clear)"
    chk suci-null-msin   "$(fld "$out" msin)"        "1234567890"
    chk suci-null-exposed "$(fld "$out" msin_exposed)" "yes"
    chk suci-null-finding "$(printf '%s\n' "$out" | grep -c '^finding	MSIN transmitted in the clear')" "1"
    chk suci-null-imsi   "$(fld "$out" imsi)" "1234567890"
    # R74: the home network identifier. A real SUCI carries MCC/MNC ahead of
    # the routing indicator, and the build side used to drop them on the floor.
    local hl
    hl=$(suci_build 0 1234567890 "" 208 01 1 0000)
    chk suci-hnid-layout "$(fld "$hl" layout)" "hnid"
    chk suci-hnid-octets "$(fld "$hl" suci_octets)" "13"
    chk suci-hnid-hex "$(fld "$hl" suci)" "0802f810000000012143658709"
    chk suci-hnid-plmn "$(fld "$hl" home_network_identifier)" "02f810"
    local hp
    hp=$(suci_parse "0802f810000000012143658709")
    chk suci-hnid-back-layout "$(fld "$hp" layout)" "hnid"
    chk suci-hnid-back-mcc "$(fld "$hp" home_mcc)" "208"
    chk suci-hnid-back-mnc "$(fld "$hp" home_mnc)" "01"
    chk suci-hnid-back-msin "$(fld "$hp" msin)" "1234567890"
    chk suci-hnid-back-ri "$(fld "$hp" routing_indicator)" "0000"
    chk suci-hnid-back-keyid "$(fld "$hp" hn_public_key_id)" "1"
    # A three-digit MNC keeps its third digit, a two-digit one uses the F pad.
    chk suci-hnid-plmn3 "$(suci_plmn_encode 310 260)" "130062"
    chk suci-hnid-plmn2 "$(suci_plmn_encode 001 01)"  "00f110"
    chk suci-plmn-bad "$(suci_plmn_encode 31 260 >/dev/null 2>&1; echo $?)" "2"
    chk suci-plmn-bad2 "$(suci_plmn_encode 310 2 >/dev/null 2>&1; echo $?)" "2"
    # The old layout is still readable, but only when asked for, and it says
    # out loud that the octets carry no home network identifier.
    hl=$(suci_build 0 1234567890 "" 208 01 1 0000 compact)
    chk suci-compact-layout "$(fld "$hl" layout)" "compact"
    chk suci-compact-hex "$(fld "$hl" suci)" "08010000002143658709"
    chk suci-compact-hnid "$(fld "$hl" home_network_identifier)" "absent"
    chk suci-compact-finding "$(printf '%s\n' "$hl" | grep -c 'carries no MCC/MNC')" "1"
    chk suci-compact-parse "$(suci_parse "08010000002143658709" compact | awk -F'\t' '$1=="layout"{print $2}')" "compact"
    chk suci-compact-msin "$(suci_parse "08010000002143658709" compact | awk -F'\t' '$1=="msin"{print $2}')" "1234567890"
    chk suci-layout-bad "$(suci_parse "08010000002143658709" sideways >/dev/null 2>&1; echo $?)" "2"
    chk suci-build-layout-bad "$(suci_build 0 1234567890 "" 208 01 1 0000 wide >/dev/null 2>&1; echo $?)" "2"

    # Profile B: 33-byte compressed ephemeral key.
    # A 33-octet compressed P-256 point: the 0x02 prefix plus 32 octets of X.
    local epk33="02${epk}"
    out=$(suci_parse "0801000202${epk33}0011223344")
    chk suci-b-scheme "$(fld "$out" protection_scheme)" "2"
    chk suci-b-name   "$(fld "$out" scheme_name)" "ECIES profile B (secp256r1)"
    chk suci-b-epklen "$(fld "$out" ephemeral_key_octets)" "33"
    chk suci-b-epk    "$(fld "$out" ephemeral_public_key)" "$epk33"
    chk suci-b-epk-len "$(printf '%s' "$epk33" | wc -c)" "66"
    # Malformed input must fail, not guess.
    chk suci-bad-nonhex "$(suci_parse zz >/dev/null 2>&1; echo $?)"  "1"
    chk suci-bad-odd    "$(suci_parse 080100010 >/dev/null 2>&1; echo $?)" "1"
    chk suci-bad-short  "$(suci_parse 0801 >/dev/null 2>&1; echo $?)" "1"
    # Routing indicator padded with 0xF is reported without the filler.
    out=$(suci_parse "0801ffff002143658709")
    chk suci-ri-unused "$(fld "$out" routing_indicator)" "0000"

    # 4. Profile A / B round trip, live crypto, SKIP (never FAIL) when the
    #    `cryptography` package is absent.
    if suci_have_cryptography; then
        local kp kp_priv kp_pub
        kp=$(suci_gen_keypair 1)
        chk keygen-a-curve  "$(fld "$kp" curve)" "X25519"
        chk keygen-a-publen "$(fld "$kp" public_key_octets)" "32"
        kp_priv=$(fld "$kp" private_key); kp_pub=$(fld "$kp" public_key)
        chk keygen-a-privlen "$(printf '%s' "$kp_priv" | wc -c)" "64"

        # Conceal then deconceal 10-digit and 9-digit MSINs.
        local enc
        enc=$(suci_conceal 1 1234567890 "$kp_pub")
        chk conceal-a-rc   "$?" "0"
        chk conceal-a-msin "$(fld "$enc" bcd_msin)" "2143658709"
        chk conceal-a-ct   "$(printf '%s' "$(fld "$enc" ciphertext)" | wc -c)" "10"
        # The key must be 16 bytes for AES-128.
        chk conceal-a-keylen "$(printf '%s' "$(fld "$enc" k_hex)" | wc -c)" "32"
        chk conceal-a-icb  "$(fld "$enc" icb)" "00000000000000000000000000000001"
        local suci_out
        suci_out=$(suci_build 1 1234567890 "$kp_pub" 208 01 1 0001)
        chk build-a-scheme "$(fld "$suci_out" scheme)" "1"
        local suci_hex; suci_hex=$(fld "$suci_out" suci)
        chk build-a-parses "$(fld "$(suci_parse "$suci_hex")" protection_scheme)" "1"
        out=$(suci_deconceal "$suci_hex" "$kp_priv")
        chk deconceal-a-msin "$(fld "$out" msin)" "1234567890"
        chk deconceal-a-scheme "$(fld "$out" scheme)" "1"
        # Round trip an odd digit count, where the BCD filler matters.
        suci_out=$(suci_build 1 123456789 "$kp_pub")
        suci_hex=$(fld "$suci_out" suci)
        chk build-a-odd-bcd "$(fld "$suci_out" bcd_msin)" "21436587f9"
        out=$(suci_deconceal "$suci_hex" "$kp_priv")
        chk deconceal-a-odd "$(fld "$out" msin)" "123456789"
        chk deconceal-a-odd-n "$(fld "$out" msin_digits)" "9"
        # Deconcealment has no integrity tag to check: ECIES here is AES-CTR
        # over BCD with no MAC, so a wrong home-network key is caught only
        # when the decrypted nibbles are not decimal digits. Measured against
        # a fixed real profile-A SUCI with random 32-octet wrong keys: 99.25%
        # caught (N=2000, 15 accepted) and 99.0% caught (N=20000, 201
        # accepted), against a 1.00% closed-form acceptance probability
        # (0.625^5 * 0.625^4 * 0.6875). So this is NOT "a wrong key always
        # fails": about 1 in 100 wrong keys decrypts to decodable BCD and is
        # reported as a bogus MSIN. Asserting the exit status would make this
        # arm fail on those. Assert the security property instead: a wrong key
        # must never yield the real MSIN.
        local kp2 kp2_priv wrong notreal
        kp2=$(suci_gen_keypair 1); kp2_priv=$(fld "$kp2" private_key)
        wrong=$(suci_deconceal "$suci_hex" "$kp2_priv" 2>/dev/null || true)
        notreal=$(fld "$wrong" msin)
        [[ "$notreal" == "1234567890" ]] && notreal="LEAKED"
        chk deconceal-a-wrongkey "$notreal" ""

        # ── the key interface refuses, and never guesses ────────────────
        # A key that is missing, unreadable, malformed or on the wrong curve
        # must each come back as its own distinct state, and the module must
        # not fall back to a weaker path. kstate() runs the same resolver
        # --deconceal uses and reduces it to one label.
        local kd p1 p2
        kd=$(mktemp -d "$MOD_TMP/keyiface.XXXXXX")
        p1=$(fld "$kp" private_key)
        p2=$(fld "$(suci_gen_keypair 2)" private_key)
        # A --genkey key file for profile A, and a P-256 key in a real PEM
        # container, which is the only form that names its own curve.
        suci_gen_keypair 1 > "$kd/a.tsv"
        python3 - "$kd/p256.pem" <<'PYV'
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as ser
open(sys.argv[1], "wb").write(ec.generate_private_key(ec.SECP256R1()).private_bytes(
    ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
PYV
        kstate() { # <profile> <key>  -> key_state label
            local o r=0
            o=$(suci_cmd_verify_hnkey "$2" "$1" 2>/dev/null) || r=$?
            if (( r == 0 )); then fld "$o" key_state; else fld "$o" key_state; fi
        }
        chk ki-missing      "$(suci_cmd_verify_hnkey "" 1 >/dev/null 2>&1; echo $?)" "2"
        chk ki-state-missing "$(kstate 1 "")" "key_missing"
        # A directory is not a key file: that is the unreadable case.
        chk ki-state-unreadable "$(kstate 1 "$kd")" "key_unreadable"
        # 63 hex digits is not a scalar, and ASCII is not a key.
        chk ki-state-malformed-hex "$(kstate 1 "$(printf 'a%.0s' $(seq 1 63))")" "key_malformed"
        chk ki-state-malformed-ascii "$(kstate 1 "not-a-key")" "key_malformed"
        # The container names the curve, so this is a real wrong-curve refusal.
        chk ki-state-wrongcurve "$(kstate 1 "$kd/p256.pem")" "key_wrong_curve"
        chk ki-state-rightcurve "$(kstate 2 "$kd/p256.pem")" "key_validated"
        chk ki-keyfile-tsv  "$(kstate 1 "$kd/a.tsv")" "key_validated"
        chk ki-hex-nocurve  "$(kstate 1 "$p2")" "key_validated"
        # A key is never accepted on the strength of the other profile's curve.
        # It has to be the container that names the curve. A bare 32-octet
        # scalar is legitimately readable as either curve, but that is a second
        # READING of the same octets, not the same key: on secp256r1 the octets
        # are a different private key with a different public key. So the row
        # must name only the profile the source is validated as, and the other
        # reading belongs in unlocks_note, which must exist for a
        # curve-agnostic source and must not exist for a container that names
        # its curve.
        chk ki-nofallback    "$(suci_cmd_verify_hnkey "$kd/p256.pem" 1 >/dev/null 2>&1; echo $?)" "4"
        local st_hex st_pem2 pub_b_scalar
        st_hex=$(suci_status "$p2")
        st_pem2=$(suci_status "$kd/p256.pem")
        pub_b_scalar=$(fld "$(suci_cmd_verify_hnkey "$p2" 2 2>/dev/null)" hn_public_key)
        chk unlocks-hex-scoped   "$(fld "$st_hex" unlocks)" "profile-a"
        chk unlocks-pem-scoped   "$(fld "$st_pem2" unlocks)" "profile-b"
        # Exactly one unlocks_note row on a curve-agnostic source...
        chk unlocks-note-hex     "$(printf '%s\n' "$st_hex" | grep -c $'^unlocks_note\t')" "1"
        # ...and none at all when the container named the curve, because there
        # is no second reading to disclaim.
        chk unlocks-note-pem     "$(printf '%s\n' "$st_pem2" | grep -c $'^unlocks_note\t')" "0"
        # The note must name the other curve AND the different public key that
        # reading produces, so a reader can see the two are not the same key.
        chk unlocks-note-other   "$(fld "$st_hex" unlocks_note | grep -c 'secp256r1')" "1"
        chk unlocks-note-pubkey  "$(fld "$st_hex" unlocks_note | grep -c "$pub_b_scalar")" "1"
        # And it must keep the condition, not become a capability claim.
        chk unlocks-note-guard   "$(fld "$st_hex" unlocks_note | grep -c 'only if they are the intended')" "1"
        # The old claim, verbatim, is gone from every row of a curve-agnostic
        # status -- including the key_note prose.
        chk unlocks-no-both      "$(printf '%s\n' "$st_hex" | grep -c 'profile-a,profile-b')" "0"

        # ── the key-dependent path, against an independent vector ────────
        # This scheme output was produced by a separate Python implementation
        # of TS 33.501 Annex C (X25519 + HKDF-SHA256 + AES-128-CTR) with fixed
        # scalars, not by this module: the module's own encoder is never in the
        # loop, so a shared bug cannot hide here. The scalars were invented for
        # this test -- no real subscriber and no real operator key.
        local vec_priv vec_hnpub vec_so vec_suci vec_out
        vec_priv="6b2f0c8d5e4a3b1908273645f1e2d3c4b5a6978877665544332211ffeeddccbb"
        vec_hnpub="ad098a6bca5d63202f93d944dd188e4f025b9ab5ff64251efa81ddfc47da1004"
        vec_so="d5e9065052939549d055acf03f348200578e3ed2b65eb6a96564471761ba4f54066dcd7c93"
        # The SUCI around it comes from this module's builder, so only the
        # scheme output -- the part the standard defines -- is external.
        vec_suci=$(fld "$(suci_build 1 1234567890 "$vec_hnpub" 208 01 1 0001)" suci)
        vec_suci="$(python3 -c "
import sys
sx = bytes.fromhex('$vec_suci'); so = bytes.fromhex('$vec_so')
sys.stdout.write((sx[:-len(so)] + so).hex())")"
        vec_out=$(suci_deconceal "$vec_suci" "$vec_priv")
        chk vector-a-msin      "$(fld "$vec_out" msin)" "1234567890"
        chk vector-a-bcd       "$(fld "$vec_out" bcd_msin)" "2143658709"
        chk vector-a-k         "$(fld "$vec_out" k_hex)" "d67f6c05b952f6e3030e47d080bad6bd"
        # The k above is fixed by the KDF; if the interface handed the module
        # the wrong scalar or the wrong curve, this cannot come out right.
        chk vector-a-hnpub     "$(fld "$vec_out" hn_public_key)" "$vec_hnpub"
        # The same vector under a key that did not conceal it must not give
        # the MSIN back.
        vec_out=$(suci_deconceal "$vec_suci" "$(fld "$(suci_gen_keypair 1)" private_key)" 2>/dev/null || true)
        chk vector-a-wrongkey "$(fld "$vec_out" msin)" ""

        # Profile B, P-256 with a compressed point.
        kp=$(suci_gen_keypair 2)
        chk keygen-b-curve  "$(fld "$kp" curve)" "secp256r1"
        chk keygen-b-publen "$(fld "$kp" public_key_octets)" "33"
        kp_priv=$(fld "$kp" private_key); kp_pub=$(fld "$kp" public_key)
        # A compressed point's prefix is 0x02 for an even Y and 0x03 for an odd
        # one, so it is a coin flip per generated key. Asserting a literal 0x02
        # made this selftest fail roughly half the time — a flaky test is worse
        # than no test, because it teaches you to ignore the failure. Assert the
        # prefix is one of the two valid values, and that the length is 33.
        chk keygen-b-compressed "$(printf '%s' "$kp_pub" | cut -c1-2 | tr 'A-F' 'a-f' | grep -cE '^(02|03)$')" "1"
        suci_out=$(suci_build 2 9876543210 "$kp_pub" 262 01 1 0002)
        chk build-b-scheme "$(fld "$suci_out" scheme)" "2"
        suci_hex=$(fld "$suci_out" suci)
        chk build-b-epklen "$(fld "$(suci_parse "$suci_hex")" ephemeral_key_octets)" "33"
        out=$(suci_deconceal "$suci_hex" "$kp_priv")
        chk deconceal-b-msin "$(fld "$out" msin)" "9876543210"
        chk deconceal-b-scheme "$(fld "$out" scheme)" "2"
        chk deconceal-b-hnpub "$(fld "$out" hn_public_key)" "$kp_pub"

        # Domain separation: two runs must not produce the same ephemeral key.
        local e1 e2
        e1=$(fld "$(suci_conceal 2 111 "$kp_pub")" ephemeral_public_key)
        e2=$(fld "$(suci_conceal 2 111 "$kp_pub")" ephemeral_public_key)
        chk conceal-random-epk "$([[ "$e1" != "$e2" ]] && echo fresh || echo reused)" "fresh"
        # The same MSIN under the same key must still differ on the wire.
        local s1 s2
        s1=$(suci_conceal 2 111 "$kp_pub" | awk -F'\t' '$1=="scheme_output"{print $2}')
        s2=$(suci_conceal 2 111 "$kp_pub" | awk -F'\t' '$1=="scheme_output"{print $2}')
        chk conceal-nondeterministic "$([[ "$s1" != "$s2" ]] && echo differs || echo same)" "differs"

        chk conceal-bad-scheme "$(suci_conceal 9 123 "$kp_pub" >/dev/null 2>&1; echo $?)" "2"
        chk conceal-bad-key    "$(suci_conceal 1 123 aabb >/dev/null 2>&1; echo $?)" "1"
        chk conceal-bad-msin   "$(suci_conceal 1 xy "$kp_pub" >/dev/null 2>&1; echo $?)" "2"
        chk deconceal-bad-scheme "$(suci_deconceal "08010100002143" "$kp_priv" >/dev/null 2>&1; echo $?)" "1"
    else
        local dep; dep=$(suci_missing_dep)
        printf 'profile-a-roundtrip\tSKIP %s not installed\n' "${dep:-python3}"
        printf 'profile-b-roundtrip\tSKIP %s not installed\n' "${dep:-python3}"
        printf 'keygen\tSKIP %s not installed\n' "${dep:-python3}"
        # The pure-python paths must still work without the package.
        # RFC 5869 test case 3 needs the full 22-octet IKM, not two bytes.
        chk no-crypto-hkdf "$(fld "$(suci_hkdf "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" "" "" 42)" okm | cut -c1-16)" "8da4e775a563c18f"
        chk no-crypto-bcd  "$(suci_msin_encode 1234567890)" "2143658709"
    fi

    # 5. Null-scheme exposure detection and the audit over a capture file.
    local auc="$d/sucis.txt"
    cat > "$auc" <<EOF
# mixed capture: one null-scheme, two concealed with a shared ephemeral key
08010000002143658709
0801000101${epk}0011223344556677
0801000101${epk}8899aabbccddeeff
EOF
    out=$(suci_audit "$auc")
    chk audit-sucis    "$(fld "$out" sucis)"        "3"
    chk audit-nulls    "$(fld "$out" null_scheme)"  "1"
    chk audit-conceal  "$(fld "$out" concealed)"    "2"
    chk audit-reused   "$(fld "$out" reused_ephemeral_keys)" "1"
    chk audit-verdict  "$(fld "$out" verdict)"      "EXPOSED"
    chk audit-null-find "$(printf '%s\n' "$out" | grep -c 'null-scheme-suci')" "1"
    chk audit-reuse-find "$(printf '%s\n' "$out" | grep -c 'reused-ephemeral-key')" "1"
    chk audit-reuse-key "$(printf '%s\n' "$out" | grep -c "count=2")" "1"

    # A capture with only concealed SUCIs and distinct keys must not be
    # reported as exposed.
    cat > "$auc" <<EOF
0801000101${epk}0011223344556677
0801000101ffeeddccbbaa99887766554433221100ffeeddccbbaa9988776655443322110011223344
EOF
    out=$(suci_audit "$auc")
    chk audit-clean-nulls "$(fld "$out" null_scheme)" "0"
    chk audit-clean-reuse "$(fld "$out" reused_ephemeral_keys)" "0"
    chk audit-clean-verdict "$(fld "$out" verdict)" "CONCEALED"

    # A file whose SUCIs are all null-scheme is the worst case.
    cat > "$auc" <<EOF
08010000002143658709
08010000009876543210
EOF
    out=$(suci_audit "$auc")
    chk audit-all-null "$(fld "$out" null_scheme)" "2"
    chk audit-all-verdict "$(fld "$out" verdict)" "EXPOSED"

    chk audit-missing  "$(suci_audit /nonexistent >/dev/null 2>&1; echo $?)" "1"
    chk audit-noargs   "$(suci_audit >/dev/null 2>&1; echo $?)" "2"
    : > "$d/empty.txt"
    chk audit-empty    "$(suci_audit "$d/empty.txt" >/dev/null 2>&1; echo $?)" "1"

    # 6. Routing indicator encode: 4 digits, or padded with 0xF.
    chk ri-0001 "$(suci_ri_encode 0001)" "0001"
    chk ri-1    "$(suci_ri_encode 1)"    "1FFF"
    chk ri-1234 "$(suci_ri_encode 1234)" "1234"
    chk ri-bad  "$(suci_ri_encode 12345 >/dev/null 2>&1; echo $?)" "2"

    # 7. Verb validation returns non-zero and never prints a success line.
    chk cli-parse-noargs   "$(suci_cmd_parse >/dev/null 2>&1; echo $?)"      "2"
    chk cli-parse-bad      "$(suci_cmd_parse zz >/dev/null 2>&1; echo $?)"   "1"
    chk cli-msinenc-noargs "$(suci_cmd_msin_encode >/dev/null 2>&1; echo $?)" "2"
    chk cli-msinenc-bad    "$(suci_cmd_msin_encode abc >/dev/null 2>&1; echo $?)" "2"
    chk cli-msindec-noargs "$(suci_cmd_msin_decode >/dev/null 2>&1; echo $?)" "2"
    chk cli-msindec-bad    "$(suci_cmd_msin_decode a1 >/dev/null 2>&1; echo $?)" "1"
    chk cli-hkdf-noargs    "$(suci_cmd_hkdf >/dev/null 2>&1; echo $?)"       "2"
    chk cli-build-noargs   "$(suci_cmd_build >/dev/null 2>&1; echo $?)"      "2"
    chk cli-build-badsch   "$(suci_cmd_build 5 123 >/dev/null 2>&1; echo $?)" "2"
    chk cli-deconc-noargs  "$(suci_cmd_deconceal >/dev/null 2>&1; echo $?)"  "2"
    chk cli-deconc-bad     "$(suci_cmd_deconceal zz aa >/dev/null 2>&1; echo $?)" "1"
    chk cli-genkey-bad     "$(suci_cmd_genkey 9 >/dev/null 2>&1; echo $?)"   "2"
    chk cli-unknown        "$(suci_cli_main --wat >/dev/null 2>&1; echo $?)" "2"

    # 8. Status TSV contract: bcd_codec is always available.
    out=$(suci_cli_status_tsv)
    chk status-bcd    "$(fld "$out" bcd_codec)" "available"
    chk status-dir    "$(fld "$out" dir)"       "$SUCI_DIR"
    chk status-keydir "$(fld "$out" keydir)"    "$SUCI_KEYDIR"
    chk status-keys   "$(printf '%s\n' "$out" | grep -c . | awk '{print ($1>=8)?"ok":"short"}')" "ok"

    # 10. The home network: SIDF + AUSF. One profile, one key store, one
    #     vector, and OpenSSL refereeing the two values the AUSF owns.
    chk hn-no-profile "$(suci_hn_deconceal 0801 >/dev/null 2>&1; echo $?)" "1"
    chk hn-show-no-profile "$(suci_hn_show >/dev/null 2>&1; echo $?)" "1"
    chk hn-create-bad-mcc "$(suci_hn_create --mcc 12 >/dev/null 2>&1; echo $?)" "2"
    chk hn-create-bad-scheme "$(suci_hn_create --scheme 7 >/dev/null 2>&1; echo $?)" "2"
    chk hn-create-bad-mnc "$(suci_hn_create --mnc 1 --mnc-digits 2 >/dev/null 2>&1; echo $?)" "2"
    chk hn-create-bad-ri "$(suci_hn_create --ri 12345 >/dev/null 2>&1; echo $?)" "2"
    if suci_have_cryptography; then
        out=$(suci_hn_create --mcc 001 --mnc 01 --mnc-digits 2 --scheme 1 --ri 0000)
        chk hn-create-rc    "$?" "0"
        chk hn-create-plmn  "$(fld "$out" plmn)" "00101"
        chk hn-create-sn    "$(fld "$out" sn_name)" "5G:mnc001.mcc001.3gppnetwork.org"
        chk hn-create-mode  "$(fld "$out" mode)" "600"
        chk hn-profile-mode "$(stat -c '%a' "$(suci_hn_profile)")" "600"
        chk hn-keyfile-mode "$(stat -c '%a' "$(suci_hn_keyfile)")" "600"
        chk hn-dir-mode     "$(stat -c '%a' "$(suci_hn_dir)")" "700"
        chk hn-create-twice "$(suci_hn_create --mcc 001 --mnc 01 >/dev/null 2>&1; echo $?)" "1"
        out=$(suci_hn_show)
        chk hn-show-key     "$(fld "$out" key_present)" "yes"
        chk hn-show-pub     "$(printf '%s' "$(fld "$out" hn_public_key)" | wc -c)" "64"

        # SIDF round trip through the profile, not through a key argument.
        local hnpub hnsuci hnout
        hnpub=$(suci_hn_pget hn_public_key)
        hnsuci=$(fld "$(suci_build 1 0123456789 "$hnpub" 001 01)" suci)
        hnout=$(suci_hn_deconceal "$hnsuci")
        chk hn-sidf-msin "$(fld "$hnout" msin)" "0123456789"
        chk hn-sidf-imsi "$(fld "$hnout" imsi)" "001010123456789"
        chk hn-sidf-supi "$(fld "$hnout" supi)" "imsi-001010123456789"
        chk hn-sidf-store-miss "$(fld "$hnout" store)" "miss"

        # AUSF: the IMSI exists in the store, so a vector can be made. The
        # RAND and SQN are TS 35.208 set 1, so AUTN and RES are published.
        local simmod="$IMSISTING_ROOT/modules/16_sim.sh"
        bash "$simmod" --key-add --imsi 001010123456789 \
            --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
            --op CDC202D5123E20F62B6D676AC72CB318 --sqn FF9BB4D0B607 >/dev/null 2>&1
        hnout=$(suci_hn_deconceal "$hnsuci")
        chk hn-sidf-store-hit "$(fld "$hnout" store)" "hit"
        out=$(suci_hn_auth "$hnsuci" 23553CBE9637A89D218AE64DAE47BF35)
        chk hn-ausf-rc       "$?" "0"
        chk hn-ausf-type     "$(fld "$out" auth_type)" "5G-AKA"
        chk hn-ausf-supi     "$(fld "$out" supi)" "imsi-001010123456789"
        chk hn-ausf-autn     "$(fld "$out" autn)" "55F328B43577B9B94A9FFAC354DFAFB3"
        chk hn-ausf-xres-len "$(printf '%s' "$(fld "$out" xres_star)" | wc -c)" "32"
        chk hn-ausf-hxres-len "$(printf '%s' "$(fld "$out" hxres_star)" | wc -c)" "32"
        chk hn-ausf-kausf-len "$(printf '%s' "$(fld "$out" kausf)" | wc -c)" "64"
        chk hn-ausf-kseaf-len "$(printf '%s' "$(fld "$out" kseaf)" | wc -c)" "64"
        chk hn-ausf-agrees   "$(fld "$out" xres_star_matches)" "yes"

        # Referee 1: XRES* through OpenSSL, keyed with CK||IK, message
        # 6B || SN || L0 || RAND || L1 || RES || L2, rightmost 128 bits.
        if command -v openssl >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1; then
            local ck ik snh xres_ref xstar_ref hx_ref
            ck=$(fld "$(suci_hn_auth "$hnsuci" 23553CBE9637A89D218AE64DAE47BF35)" kausf)
            # Reuse the responder directly for CK and IK: the auth verb does
            # not print them, and a referee must not need them printed.
            local resp
            resp=$(bash "$simmod" --aka-responder --imsi 001010123456789 \
                        --rand 23553CBE9637A89D218AE64DAE47BF35 \
                        --5g --sn-name '5G:mnc001.mcc001.3gppnetwork.org' 2>/dev/null)
            local ckv ikv resv
            ckv=$(awk -F'\t' '$1=="ck"{print $2}' <<< "$resp")
            ikv=$(awk -F'\t' '$1=="ik"{print $2}' <<< "$resp")
            resv=$(awk -F'\t' '$1=="xres"{print $2}' <<< "$resp")
            snh=$(printf '%s' '5G:mnc001.mcc001.3gppnetwork.org' | od -An -tx1 | tr -d ' \n')
            xstar_ref=$(printf '%s' "6b${snh}010023553CBE9637A89D218AE64DAE47BF35 0080${resv}0040" | tr -d ' ' |
                        xxd -r -p | openssl dgst -sha256 -mac HMAC \
                            -macopt hexkey:"${ckv}${ikv}" 2>/dev/null | sed 's/^.*= //')
            xstar_ref=${xstar_ref^^}
            xstar_ref="${xstar_ref:32}"
            chk hn-xres-openssl "$(fld "$out" xres_star)" "$xstar_ref"
            # Referee 2: HXRES* = rightmost 128 of SHA-256(RAND || XRES*).
            hx_ref=$(printf '%s' "23553CBE9637A89D218AE64DAE47BF35${xstar_ref}" |
                     xxd -r -p | openssl dgst -sha256 2>/dev/null | sed 's/^.*= //')
            hx_ref=${hx_ref^^}
            hx_ref="${hx_ref:32}"
            chk hn-hxres-openssl "$(fld "$out" hxres_star)" "$hx_ref"
        else
            printf 'hn-xres-openssl\tSKIP no openssl/xxd\n'
            printf 'hn-hxres-openssl\tSKIP no openssl/xxd\n'
        fi

        # A SUCI for an IMSI the store does not hold must refuse, by name.
        local stray
        stray=$(fld "$(suci_build 1 999999999 "$hnpub" 001 01)" suci)
        chk hn-ausf-no-store "$(suci_hn_auth "$stray" >/dev/null 2>&1; echo $?)" "1"
        chk hn-auth-bad-rand "$(suci_hn_auth "$hnsuci" zz >/dev/null 2>&1; echo $?)" "2"
        chk hn-auth-noargs   "$(suci_hn_auth >/dev/null 2>&1; echo $?)" "2"

        # The resident home network: one SUCI asked twice, so the SQN moves.
        local sr1 sr2
        sr1=$(printf 'SUCI %s\nQUIT\n' "$hnsuci" | suci_hn_serve 2>/dev/null)
        chk hn-serve-ready "$(fld "$sr1" served)" "ready"
        chk hn-serve-sidf  "$(printf '%s\n' "$sr1" | grep -c '^role	SIDF')" "1"
        chk hn-serve-bye   "$(printf '%s\n' "$sr1" | grep -c '^served	bye')" "1"
        sr2=$(printf 'AUTH %s\nAUTH %s\nQUIT\n' "$hnsuci" "$hnsuci" | suci_hn_serve 2>/dev/null)
        chk hn-serve-auths "$(printf '%s\n' "$sr2" | grep -c '^role	AUSF')" "2"
    else
        local dep; dep=$(suci_missing_dep)
        printf 'hn-profile\tSKIP %s not installed\n' "${dep:-python3}"
        printf 'hn-ausf\tSKIP %s not installed\n' "${dep:-python3}"
    fi

    # 10. The linkability oracle. Signatures are pure string tests, so the
    #     fixtures run with or without python3: only the concealing side needs it.
    local obsf lf
    obsf="$d/link"
    mkdir -p "$obsf"
    # scheme-0 SUCIs need no key at all
    local ns1 ns2 ns3
    ns1=$(suci_build 0 0123456789 "" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    ns2=$(suci_build 0 0987654321 "" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    ns3=$(suci_build 0 0123456789 "" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
    printf '%s\t%s\n%s\t%s\n' "n1" "$ns1" "n2" "$ns2" > "$obsf/null-pair.tsv"
    printf '%s\t%s\n%s\t%s\n' "n1" "$ns1" "n2" "$ns3" > "$obsf/null-same.tsv"
    chk link-null-diff "$(suci_link_oracle "$obsf/null-pair.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "NOT-LINKED"
    chk link-null-same "$(suci_link_oracle "$obsf/null-same.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "LINKABLE"
    chk link-null-by   "$(suci_link_oracle "$obsf/null-same.tsv" | awk -F'\t' '$1=="linked_by"{v=$2} END{print v}')" "suci"
    chk link-null-clear "$(suci_link_oracle "$obsf/null-same.tsv" | awk -F'\t' '$1=="cleartext_msin"{v=$2} END{print v}')" "2"
    chk link-null-finding "$(suci_link_oracle "$obsf/null-same.tsv" | grep -c '^finding	cleartext-msin')" "1"
    chk link-length-weak "$(suci_link_oracle "$obsf/null-pair.tsv" | awk -F'\t' '$1=="weak"{print $2}')" "msin_length"
    chk link-length-note "$(suci_link_oracle "$obsf/null-pair.tsv" | grep -c 'same length, which is a digit count')" "1"
    chk link-noargs "$(suci_link_oracle >/dev/null 2>&1; echo $?)" "2"
    chk link-missing-file "$(suci_link_oracle "$d/nope.tsv" >/dev/null 2>&1; echo $?)" "1"
    printf 'a\n\n# comment only\n' > "$obsf/empty.tsv"
    printf '\n   \n# comment only\n' > "$obsf/empty.tsv"
    chk link-no-observations "$(suci_link_oracle "$obsf/empty.tsv" >/dev/null 2>&1; echo $?)" "1"
    printf '%s\t%s\n' "x" "nothex" > "$obsf/bad.tsv"
    chk link-junk-only "$(suci_link_oracle "$obsf/bad.tsv" >/dev/null 2>&1; echo $?)" "1"
    # junk beside a good observation is reported and skipped, not fatal
    printf '%s\t%s\n%s\t%s\n' "x" "nothex" "good" "$ns1" > "$obsf/bad-plus-good.tsv"
    chk link-junk-count "$(suci_link_oracle "$obsf/bad-plus-good.tsv" | awk -F'\t' '$1=="unparseable" && NF==2 {v=$2} END{print v}')" "1"
    chk link-junk-keeps-good "$(suci_link_oracle "$obsf/bad-plus-good.tsv" | awk -F'\t' '$1=="observations"{v=$2} END{print v}')" "1"
    chk link-demo-no-profile "$(STATE_DIR="$d/none" TMP_DIR="$d/nonetmp" suci_link_demo >/dev/null 2>&1; echo $?)" "1"
    if suci_have_cryptography; then
        local pub2 sa sb sreuse head2 tail2 n
        pub2=$(suci_hn_pget hn_public_key)
        sa=$(suci_build 1 0123456789 "$pub2" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
        sb=$(suci_build 1 0987654321 "$pub2" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
        n=$(suci_build 1 1111111111 "$pub2" 001 01 1 0000 | awk -F'\t' '$1=="suci"{print $2}')
        printf 'a\t%s\nb\t%s\n' "$sa" "$sb" > "$obsf/fresh.tsv"
        chk link-fresh-pairs "$(suci_link_oracle "$obsf/fresh.tsv" | awk -F'\t' '$1=="pairs"{v=$2} END{print v}')" "1"
        chk link-fresh-verdict "$(suci_link_oracle "$obsf/fresh.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "NOT-LINKED"
        chk link-fresh-eph "$(suci_link_oracle "$obsf/fresh.tsv" | awk -F'\t' '$1=="identifying"{print $2}')" ""
        chk link-fresh-herd "$(suci_link_oracle "$obsf/fresh.tsv" | grep -c '^shared_by_network')" "3"
        # same SUCI twice: the concealment was not refreshed
        printf 'a\t%s\nb\t%s\n' "$sa" "$sa" > "$obsf/repeat.tsv"
        chk link-repeat-verdict "$(suci_link_oracle "$obsf/repeat.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "LINKABLE"
        chk link-repeat-count "$(suci_link_oracle "$obsf/repeat.tsv" | awk -F'\t' '$1=="repeated_sucis"{v=$2} END{print v}')" "1"
        chk link-repeat-finding "$(suci_link_oracle "$obsf/repeat.tsv" | grep -c '^finding	repeated-suci')" "1"
        # the reused ephemeral key: same scheme output, re-randomised ciphertext
        # header 5 octets (compact) or 8 (hnid) then a 32-octet X25519 key
        local hdr2=74
        [[ "$(suci_parse "$sa" | awk -F'\t' '$1=="layout"{print $2}')" == "hnid" ]] && hdr2=80
        head2="${sa:0:$hdr2}"; tail2="${sa:$hdr2}"
        sreuse="$head2$(printf '%s' "$tail2" | rev)"
        printf 'a\t%s\nb\t%s\n' "$sa" "$sreuse" > "$obsf/reuse.tsv"
        chk link-reuse-verdict "$(suci_link_oracle "$obsf/reuse.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "LINKABLE"
        chk link-reuse-by "$(suci_link_oracle "$obsf/reuse.tsv" | awk -F'\t' '$1=="linked_by"{v=$2} END{print v}')" "eph_key"
        chk link-reuse-count "$(suci_link_oracle "$obsf/reuse.tsv" | awk -F'\t' '$1=="reused_ephemeral_keys"{v=$2} END{print v}')" "1"
        # One subscriber seen once with the null scheme and once concealed: the
        # oracle does not join those, and says so rather than guessing.
        printf 'n\t%s\nc\t%s\n' "$ns1" "$sa" > "$obsf/mixed.tsv"
        chk link-mixed-verdict "$(suci_link_oracle "$obsf/mixed.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "NOT-LINKED"
        chk link-mixed-note "$(suci_link_oracle "$obsf/mixed.tsv" | grep -c 'share nothing but the home network')" "1"
        # one vector handed to two rounds: the AUTN is the identifying signal
        printf 'a\t%s\t%s\nb\t%s\t%s\n' "$sa" "B1FC39F26D89B9B9B0888D16DCE843A1" \
            "$n" "B1FC39F26D89B9B9B0888D16DCE843A1" > "$obsf/av.tsv"
        chk link-av-verdict "$(suci_link_oracle "$obsf/av.tsv" | awk -F'\t' '$1=="verdict"{v=$2} END{print v}')" "LINKABLE"
        chk link-av-by "$(suci_link_oracle "$obsf/av.tsv" | awk -F'\t' '$1=="linked_by"{v=$2} END{print v}')" "autn"
        chk link-av-count "$(suci_link_oracle "$obsf/av.tsv" | awk -F'\t' '$1=="repeated_autn"{v=$2} END{print v}')" "1"
        chk link-av-finding "$(suci_link_oracle "$obsf/av.tsv" | grep -c '^finding	repeated-authentication-vector')" "1"
        # the demo builds its own fixture and must agree with all five cases
        local demo
        demo=$(suci_link_demo)
        chk demo-rc "$?" "0"
        chk demo-cases "$(printf '%s\n' "$demo" | grep -c '^case	')" "5"
        chk demo-agree "$(printf '%s\n' "$demo" | awk -F'\t' '
            $1=="expected"{ e=$2; next }
            $1=="actual"{ if (e != $2) bad++; e="" }
            END{ print bad+0 }')" "0"
        chk demo-fresh "$(printf '%s\n' "$demo" | awk -F'\t' '$1=="case"&&$2=="fresh-concealment"{c=1;next} c&&$1=="actual"{print $2;exit}')" "NOT-LINKED"
        chk demo-reuse "$(printf '%s\n' "$demo" | awk -F'\t' '$1=="case"&&$2=="reused-ephemeral-key"{c=1;next} c&&$1=="actual"{print $2;exit}')" "LINKABLE"
        chk demo-null "$(printf '%s\n' "$demo" | awk -F'\t' '$1=="case"&&$2=="null-scheme"{c=1;next} c&&$1=="actual"{print $2;exit}')" "LINKABLE"
        chk demo-av "$(printf '%s\n' "$demo" | awk -F'\t' '$1=="case"&&$2=="same-authentication-vector"{c=1;next} c&&$1=="actual"{print $2;exit}')" "LINKABLE"
        chk demo-reuse-by "$(printf '%s\n' "$demo" | awk -F'\t' '$1=="linked_by"{print $2;exit}')" "eph_key"
    else
        printf 'link-fixtures\tSKIP %s not installed\n' "$(suci_missing_dep)"
    fi

    # 9. TSV injection: a tab in an untrusted string must not forge a row.
    local evil
    evil=$(suci_sanitize $'001\tfake\trow\nmore')
    chk sanitize-tabs "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "1"
    chk sanitize-nl   "$(printf '%s' "$evil" | grep -c .)" "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
suci_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== SUCI Deconcealment ===${C_RESET}"
        echo -e "  python3:     ${C_GRN}$(suci_have_python && echo yes || echo missing)${C_RESET}"
        echo -e "  cryptography:${C_GRN}$(suci_have_cryptography && echo present || echo 'missing — profile A/B will SKIP')${C_RESET}"
        echo -e "  keys: ${C_DIM}$SUCI_KEYDIR${C_RESET}\n"
        cat << 'M'
  [1]  parse a SUCI
  [2]  build a SUCI (scheme 0 / profile A / profile B)
  [3]  deconceal a SUCI with the home network private key
  [4]  generate a home network key pair
  [5]  HKDF-SHA256
  [6]  MSIN BCD encode
  [7]  MSIN BCD decode
  [8]  audit a file of SUCIs (exposure / linkability)
  [9]  status
  [10] verify a home-network private key (the last hop)
  [11] become a home network (profile: PLMN, RI, concealment key)
  [12] show the home network profile
  [13] SIDF: deconceal a SUCI with the profile
  [14] AUSF: one 5G-AKA event for a SUCI
  [15] serve a home network on stdin
  [16] linkability oracle over a file of SUCIs
  [17] linkability demo (build the fixture, then judge it)
  [0]  back

M
        local c
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  SUCI hex> " h
               suci_cmd_parse "$h" | column -t -s$'\t' 2>/dev/null || suci_cmd_parse "$h"
               read -rp "  press enter " _ ;;
            2)
                read -rp "  scheme (0|null, 1|profile A, 2|profile B)> " s
                read -rp "  MSIN> " m
                read -rp "  home network public key hex (blank for scheme 0)> " k
                read -rp "  MCC (001)> " a
                read -rp "  MNC (01)> " b
                suci_cmd_build "${s:-1}" "$m" "$k" "${a:-001}" "${b:-01}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            3)
                read -rp "  SUCI hex> " h
                read -rp "  home network private key hex> " k
                suci_cmd_deconceal "$h" "$k" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4)
                read -rp "  scheme (1|profile A, 2|profile B)> " s
                suci_cmd_genkey "${s:-1}" "$SUCI_KEYDIR/hn_scheme${s:-1}.key" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            5)
                read -rp "  IKM hex> " i
                read -rp "  salt hex (blank for none)> " s
                read -rp "  info> " n
                read -rp "  length (32)> " l
                suci_cmd_hkdf "$i" "$s" "$n" "${l:-32}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            6) read -rp "  MSIN digits> " m
               suci_cmd_msin_encode "$m" | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            7) read -rp "  BCD hex> " h
               suci_cmd_msin_decode "$h" | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            8) read -rp "  SUCI list file> " f
               suci_cmd_audit "$f" | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            9) suci_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            10) read -rp "  key hex or key file> " k
                read -rp "  profile (1|X25519, 2|secp256r1)> " p
                suci_cmd_verify_hnkey "$k" "${p:-1}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            11) read -rp "  MCC (001)> " mcc
                read -rp "  MNC (01)> " mnc
                read -rp "  MNC digits (2)> " md
                read -rp "  scheme (1|profile A, 2|profile B)> " sc
                read -rp "  routing indicator (0000)> " ri
                suci_hn_create --mcc "${mcc:-001}" --mnc "${mnc:-01}" \
                    --mnc-digits "${md:-2}" --scheme "${sc:-1}" --ri "${ri:-0000}" \
                    | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            12) suci_hn_show | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            13) read -rp "  SUCI hex> " h
                suci_hn_deconceal "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            14) read -rp "  SUCI hex> " h
                read -rp "  RAND hex (blank to draw one)> " r
                suci_hn_auth "$h" "$r" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            15) suci_hn_serve ;;
            16) read -rp "  observation file> " f
                suci_link_oracle "$f" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            17) suci_link_demo | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
suci_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    suci_cli_status_tsv "${1:-}" ;;
        --build-suci)    suci_cmd_build "${1:-1}" "${2:-}" "${3:-}" "${4:-001}" "${5:-01}" ;;
        --parse-suci)    suci_cmd_parse "${1:-}" ;;
        --deconceal)     suci_cmd_deconceal "${1:-}" "${2:-}" ;;
        --verify-hnkey)  suci_cmd_verify_hnkey "${1:-}" "${2:-1}" ;;
        --hkdf)          suci_cmd_hkdf "${1:-}" "${2:-}" "${3:-}" "${4:-32}" ;;
        --msin-encode)   suci_cmd_msin_encode "${1:-}" ;;
        --msin-decode)   suci_cmd_msin_decode "${1:-}" ;;
        --audit)         suci_cmd_audit "${1:-}" ;;
        --genkey)        suci_cmd_genkey "${1:-1}" "${2:-}" ;;
        --hn-create)     suci_hn_create "$@" ;;
        --hn-show)       suci_hn_show ;;
        --hn-deconceal)  suci_hn_deconceal "${1:-}" ;;
        --hn-auth)       suci_hn_auth "${1:-}" "${2:-}" ;;
        --hn-serve)      suci_hn_serve ;;
        --link-oracle)   suci_link_oracle "${1:-}" ;;
        --link-demo)     suci_link_demo ;;
        --conceal)       suci_conceal "${1:-1}" "${2:-}" "${3:-}" ;;
        --selftest)      suci_selftest ;;
        --menu)          suci_menu ;;
        *)
            cat >&2 <<EOF
SUCI Deconcealment — concealment, deconcealment, exposure audit

Usage: $0 COMMAND
  --status-tsv [key-hex|keyfile]     availability, the key interface and the last hop
                                     as TSV; with an argument, validates that key source
  --build-suci <0|1|2> <msin> [hn-pubkey-hex] [mcc] [mnc]
                                     build a SUCI (0 null, 1 profile A, 2 profile B)
  --parse-suci <hex> [layout]        parse the SUCI fields (layout: hnid, compact
                                     or auto -- real SUCI carries MCC/MNC ahead of
                                     the routing indicator; the compact layout this
                                     module first shipped carries none); flags a
                                     null scheme
  --deconceal <hex> <key-hex|keyfile>
                                     recover the MSIN with the home network private
                                     key; env IMSISTING_SUCI_HN_KEY=<keyfile> also works
  --verify-hnkey <key-hex|keyfile> [1|2]
                                     validate a home network private key against the
                                     profile's curve and report what it is
  --hkdf <ikm-hex> <salt-hex|-> <info> [len]
                                     HKDF-SHA256, extract then expand (RFC 5869)
  --msin-encode <msin>               decimal MSIN to nibble-swapped BCD
  --msin-decode <hex>                BCD back to the MSIN, dropping the 0xF filler
  --audit <sucis-file>               find null-scheme exposure and reused ephemeral keys
  --genkey <1|2> [outfile]           generate a home network key pair
  --hn-create [--mcc 001] [--mnc 01] [--mnc-digits 2|3] [--scheme 1|2]
              [--ri 0000] [--keyfile <file>] [--force]
                                     make this host a home network: PLMN, routing
                                     indicator, concealment key. Already there
                                     is refused unless --force
  --hn-show                          the profile, with the key's presence
  --hn-deconceal <suci-hex>          SIDF: the profile's key turns the SUCI back
                                     into a SUPI and looks the IMSI up in the store
  --hn-auth <suci-hex> [rand-hex]    AUSF: one 5G-AKA event end to end -- SIDF, the
                                     K store, RAND||AUTN, XRES*, HXRES*, KAUSF, KSEAF
  --hn-serve                         resident home network on stdin: SUCI, AUTH,
                                     SHOW, QUIT (one line each)
  --link-oracle <obs-file>           pairwise linkability over observed SUCIs: for
                                     every pair, linked or not, and by which signal
                                     -- the SUCI itself, the ephemeral key, a
                                     cleartext MSIN, the MSIN's length class, an
                                     AUTN two rounds were both given, or nothing
  --link-demo                        build the fixture on this host's own home
                                     network and run the oracle on it: six rounds,
                                     two subscribers, one reused ephemeral key
  --conceal <1|2> <msin> <hn-pubkey-hex>
                                     the raw ECIES concealment
  --selftest                         RFC 5869 vectors, BCD round trips, profile A/B
  --menu                             interactive menu

Profile A/B need python3 with the 'cryptography' package; HKDF and the BCD
codec are pure hashlib/hmac and always run.

The last hop: recovering a subscriber's MSIN needs the home network's private
key for the profile that concealed it (X25519 for profile A, secp256r1 for
profile B). It is held by the operator, or obtained from it. Everything else
here -- parsing, the null-scheme audit, the reused-ephemeral audit, HKDF, the
MSIN codec and concealment -- runs without it. A key that is missing,
unreadable, malformed or on the wrong curve is refused with its own exit code
(2, 3, 1, 4); nothing falls back to a weaker path. The key arrives as the
second argument (hex scalar or key file: --genkey TSV, bare hex, PEM or DER)
or through IMSISTING_SUCI_HN_KEY=<keyfile>.
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
    suci_cli_main "$@"
fi
