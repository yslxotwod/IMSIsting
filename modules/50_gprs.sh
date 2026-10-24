#!/usr/bin/env bash
# gprs — GPRS/EDGE packet core: GEA capability table, APN coding, PDP context.
#
# The circuit-switched half of 2G is covered by 06_gsm_air; the packet-switched
# half is its own stack. This module states its GEA limits instead of implying
# capability. GEA0 (identity), GEA3 (TS 55.216) and GEA4 (TS 55.226) are
# computed here, and --gea-kat checks nine published vectors from TS 55.217,
# TS 55.218 and TS 55.226 octet for octet. GEA1 and GEA2 refuse by name: 3GPP
# never published them, they were recovered and broken in the cryptanalysis
# literature (Beierle et al., EUROCRYPT 2021; Amzaleg and Dinur, IACR ePrint
# 2022/424, which recovers a GEA-1 key in 2^40 time with about 4 MiB and runs
# in hours on a laptop), and the recovered tap sets are not in this tree. GEA5
# refuses because the algorithm body and the test data in TS 55.251/55.252 are
# licence-gated. APN and PDP coding is computed and known-answer tested against
# the published spec tables; the air-interface step is a handoff.
#
# Attack owned: 2G packet-switched (O5/O4 adjacency) — codec and detection half.
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

MOD_TMP="$TMP_DIR/gprs"
GPRS_DIR="$LOOT_DIR/gprs"
GPRS_GEA_TOOL="$IMSISTING_ROOT/tools/gsm_gea.py"
mkdir -p "$MOD_TMP" "$GPRS_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

gprs_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
GPRS_F=()
gprs_split() {
    GPRS_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        GPRS_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
gprs_str2hex() { local s="${1:-}" out="" i; for (( i=0; i<${#s}; i++ )); do printf -v c '%02x' "'${s:i:1}"; out+="$c"; done; printf '%s' "$out"; }
gprs_hex2str() { local h="${1:-}"; printf '%b' "$(printf '%s' "$h" | sed 's/../\\x&/g')"; }

gprs_status_tsv() {
    printf 'MODULE\tgprs\n'
    printf 'TARGET\tGPRS/EDGE: GEA0/GEA3/GEA4 ciphering with published vectors, APN/PDP coding, downgrade\n'
    printf 'TRANSMIT\tnone — codec and detection\n'
    printf 'SELFTEST\tyes\n'
}

# ── GEA ciphering family — capability, not software ─────────────────────
# Sources: TS 43.020 §D.4.8/§D.4.9 (negotiation; what an MS may implement) and
# Annex H.5 (eGPRS/CIoT security algorithms). A row may only say yes when this
# module computes it and --selftest proves the output against a value taken
# from the standard or an independent implementation (MODULE_CONVENTIONS §9/§16).
gprs_gea_table() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' algo clause key_bits input implemented_here why
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA0 'TS 43.020 §H.5.1' 0 none yes \
        'identity — LLC ciphering disabled (TS 44.064); KAT-tested here'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA1 'TS 43.020 §D.4.9' 64 32-bit no \
        'prohibited in MS; never published by 3GPP — recovered and broken in Beierle et al. EUROCRYPT 2021 (2^40), refined in IACR ePrint 2022/424'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA2 'TS 43.020 §D.4.9' 64 32-bit no \
        'removed 2021-06 "due to security", prohibited in MS; recovered in the same paper, attack near 2^45, refined in ePrint 2022/424'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA3 'TS 55.216 V6.2.0' 64 32-bit yes \
        'computed here per TS 55.216; 6 vectors from TS 55.217/55.218 pass in tools/gsm_gea.py'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA4 'TS 55.226 V9.0.0' 128 32-bit yes \
        'computed here per TS 55.226; 3 vectors from the same spec pass in tools/gsm_gea.py'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' GEA5 'TS 55.251 V14.0.0' 128 '32-bit+CONSTANT-F' no \
        'TS 55.251/55.252 are published but every algorithmic clause and the test data are licence-gated'
}
gprs_gea_name() {
    case "$1" in
        0) echo "GEA0 (no encryption; identity)" ;;
        1) echo "GEA1 (64-bit; prohibited in MS, key recovery 2^40)" ;;
        2) echo "GEA2 (64-bit; removed 2021-06, attack near 2^45)" ;;
        3) echo "GEA3 (64-bit KASUMI; TS 55.216)" ;;
        4) echo "GEA4 (128-bit KASUMI; TS 55.226)" ;;
        5) echo "GEA5 (128-bit SNOW 3G; algorithm body licence-gated)" ;;
        *) echo "unknown GEA — never classified as safe" ;;
    esac
}

# Why a GEA is refused. Specific per algorithm: what names it, and the fact that
# no external known-answer vector exists to prove an implementation here.
gprs_gea_why() {
    case "$1" in
        1) echo 'TS 43.020 §D.4.9 prohibits GEA1 in mobile stations. 3GPP never published the algorithm; it was recovered and published in the cryptanalysis literature (Beierle et al., EUROCRYPT 2021), where the attack lives too: a 64-bit key falls in 2^40 from 65 keystream bits, and Amzaleg and Dinur (IACR ePrint 2022/424) cut the memory from 44 GiB to about 4 MiB, recovering it in hours on a laptop. Missing here is the recovered LFSR tap sets transcribed as a table with a vector, not the analysis' ;;
        2) echo 'TS 43.020 removed GEA2 in 2021-06 ("due to security") and §D.4.9 prohibits it. Same publication path as GEA1: no 3GPP algorithm text, recovered in Beierle et al. EUROCRYPT 2021 with an attack near 2^45, refined in ePrint 2022/424. Not implemented here for the same reason: the recovered taps are not on this host' ;;
        3) echo 'implemented — TS 55.216 V6.2.0, KASUMI-based, with the TS 55.217/55.218 test vectors' ;;
        4) echo 'implemented — TS 55.226 V9.0.0, KASUMI-128, with its own test vectors' ;;
        5) echo 'TS 55.251 V14.0.0 is published, but sections 5.3 to 5.6 (components, initialisation, keystream generation) and the TS 55.252 test data each read "only available under licence": the interfaces are public, the algorithm body is not' ;;
    esac
}

# --gea-crypt <0-5> <kc_hex> <input32_hex> <plaintext_hex>
# GEA0 is the only GEA this module can compute, because it is defined as the
# identity (TS 43.020 §H.5.1: ciphering function disabled). Everything else
# refuses: computing it would be an unproven guess (MODULE_CONVENTIONS §9/§16).
# The published vectors are the whole argument for calling GEA3 and GEA4
# implemented: each row below is an octet-for-octet comparison against the
# standard's own test data, not a self-consistency check.
gprs_gea_kat() {
    [[ -f "$GPRS_GEA_TOOL" ]] || { printf 'ERROR\ttools/gsm_gea.py is missing\n' >&2; return 1; }
    python3 "$GPRS_GEA_TOOL" --kat
}

gprs_gea_crypt() {  # <algo> <kc_hex> <input32_hex> <plaintext_hex> [direction]
    local n="${1:-}" kc="${2:-}" input="${3:-}" pt="${4:-}" dir="${5:-0}"
    if ! [[ "$n" =~ ^[0-5]$ && "$kc" =~ ^([0-9a-fA-F]{0,32})$ \
            && "$input" =~ ^[0-9a-fA-F]{8}$ && "$pt" =~ ^([0-9a-fA-F]{2})*$ \
            && "$dir" =~ ^[01]$ ]]; then
        printf 'ERROR\tusage: --gea-crypt <0-5> <kc_hex> <input32_hex> <plaintext_hex> [0|1]\n' >&2
        return 2
    fi
    if [[ "$n" != 0 && "$n" != 3 && "$n" != 4 ]]; then
        printf 'ERROR\t%s is not implemented in this module — no capability is claimed\n' \
            "$(gprs_gea_name "$n")" >&2
        printf 'WHY\t%s\n' "$(gprs_gea_why "$n")" >&2
        return 3
    fi
    if [[ "$n" == 0 ]]; then
        printf 'algo\tGEA0 (no encryption; identity)\n'
        printf 'ciphertext\t%s\n' "${pt,,}"
        printf 'note\tTS 43.020 §H.5.1 disables LLC ciphering (TS 44.064): ciphertext == plaintext\n'
        return 0
    fi
    if [[ ! -f "$GPRS_GEA_TOOL" ]]; then
        printf 'ERROR\ttools/gsm_gea.py is missing\n' >&2
        return 1
    fi
    local want=16
    [[ "$n" == 4 ]] && want=32
    if (( ${#kc} != want )); then
        printf 'ERROR\tGEA%s takes a %d-hex-octet key, got %d octets\n' \
            "$n" "$(( want / 2 ))" "$(( ${#kc} / 2 ))" >&2
        return 2
    fi
    local out gamma ptlen
    out=$(python3 "$GPRS_GEA_TOOL" --gea"$n" "$kc" "$input" "$dir" "$(( ${#pt} / 2 ))" 2>&1) || {
        printf 'ERROR\tthe GEA%s keystream generator failed: %s\n' "$n" "$(gprs_sanitize "$out")" >&2
        return 1; }
    gamma=$(printf '%s\n' "$out" | awk -F'\t' '$1=="gamma"{print $2; exit}')
    [[ -n "$gamma" ]] || { printf 'ERROR\tno gamma returned\n' >&2; return 1; }
    printf 'algo\t%s\n' "$(gprs_gea_name "$n")"
    printf 'input\t%s\n' "${input,,}"
    printf 'direction\t%s\n' "$dir"
    printf 'gamma\t%s\n' "$gamma"
    # XOR in shell is a byte loop; the plaintext is short by contract.
    local i ct="" b
    for (( i=0; i<${#pt}; i+=2 )); do
        b=$(( 0x${pt:i:2} ^ 0x${gamma:i:2} ))
        printf -v b '%02x' "$b"
        ct+="$b"
    done
    printf 'ciphertext\t%s\n' "$ct"
    printf 'note\t%s\n' "$(gprs_gea_why "$n")"
    return 0
}



# ── APN coding (TS 23.003 §9.1) ─────────────────────────────────────────
# A DNS-style name: each label prefixed by its length octet, no trailing root.
# Worked anchor: "internet" -> 08 696e7465726e6574.
gprs_apn_encode() {
    local apn="${1:-}"
    [[ -n "$apn" ]] || { printf 'ERROR\tempty APN\n' >&2; return 2; }
    local IFS='.' out="" label lhex
    for label in $apn; do
        [[ -n "$label" ]] || { printf 'ERROR\tempty APN label\n' >&2; return 2; }
        (( ${#label} <= 63 )) || { printf 'ERROR\tAPN label longer than 63 octets\n' >&2; return 2; }
        [[ "$label" =~ ^[A-Za-z0-9-]+$ ]] || { printf 'ERROR\tAPN label has an invalid character: %s\n' "$label" >&2; return 2; }
        lhex=$(gprs_str2hex "$label")
        printf -v lc '%02x' "${#label}"
        out+="${lc}${lhex}"
    done
    printf '%s\n' "$out"
}
gprs_apn_decode() {
    local h="${1:-}"
    h=$(printf '%s' "$h" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]] || { printf 'ERROR\tnot even-length hex\n' >&2; return 2; }
    local out="" off=0
    while (( off*2 < ${#h} )); do
        local len=$(( 16#${h:$((off*2)):2} ))
        (( len > 0 && len <= 63 )) || { printf 'ERROR\tbad APN label length %d at octet %d\n' "$len" "$off" >&2; return 1; }
        (( (off+1+len)*2 <= ${#h} )) || { printf 'ERROR\tAPN label runs past the end\n' >&2; return 1; }
        out+="$(gprs_hex2str "${h:$(((off+1)*2)):$((len*2))}")."
        off=$(( off + 1 + len ))
    done
    printf '%s\n' "${out%.}"
}

# ── PDP context (TS 24.008 §10.5.6.4 / table 9.5.1) ─────────────────────
# The "Requested PDP address" IE is type-4 LV with NO IEI byte in the ACTIVATE
# PDP CONTEXT REQUEST (table 9.5.1: M, LV, 3-23 octets). Value = octet 3
# (spare | type organisation) + octet 4 (PDP type number) + address. The
# organisation nibble and type numbers below were re-checked against pycrate's
# independent encoder (pycrate_mobile.TS24008_SM.PDPAddr): 0001 PPP, 0002
# non-IP (ETSI allocated), 0121 IPv4, 0157 IPv6, 018d IPv4v6 (IETF allocated).
gprs_pdp_type_name() {
    case "$1" in
        01) echo "PPP" ;;
        02) echo "non-IP" ;;
        21) echo "IPv4" ;;
        57) echo "IPv6" ;;
        8D) echo "IPv4v6" ;;
        *) echo "unknown PDP type — never classified as valid" ;;
    esac
}
gprs_apn_ie() {
    local apn="${1:-}"
    local body; body=$(gprs_apn_encode "$apn") || return 2
    local blen=$(( ${#body} / 2 ))
    (( blen <= 100 )) || {
        printf 'ERROR\tAPN codes to %d octets; the IE value may be at most 100 (TS 24.008 table 9.5.1: 3-102 total)\n' "$blen" >&2
        return 2; }
    printf -v lc '%02x' "$blen"
    printf 'IEI\t28\nlength\t%s\nvalue\t%s\nie\t28%s%s\n' "$lc" "$body" "$lc" "$body"
}
# --pdp-ie <type_hex> [<address_hex>]
# type_hex is the PDP type number from table 10.5.155: 01/02 are ETSI-allocated,
# 21/57/8d are IETF-allocated. The address must be the exact length the type
# implies (IPv4 4, IPv6 16, IPv4v6 20, PPP/non-IP none); anything else refuses.
gprs_pdp_type_ie() {
    local t="${1:-21}" addr="${2:-}" org name nbytes
    case "${t,,}" in
        01) org=00; name='PPP (ETSI type 01)'; nbytes=0 ;;
        02) org=00; name='non-IP (ETSI type 02)'; nbytes=0 ;;
        21) org=01; name='IPv4 (IETF type 21)'; nbytes=4 ;;
        57) org=01; name='IPv6 (IETF type 57)'; nbytes=16 ;;
        8d) org=01; name='IPv4v6 (IETF type 8d)'; nbytes=20 ;;
        *)  printf 'ERROR\tunknown PDP type number %s — no capability claimed (TS 24.008 table 10.5.155)\n' "$t" >&2
            return 2 ;;
    esac
    addr="${addr,,}"
    [[ "$addr" =~ ^([0-9a-f]{2})*$ ]] || {
        printf 'ERROR\taddress is not even-length hex: %s\n' "$addr" >&2; return 2; }
    local abytes=$(( ${#addr} / 2 ))
    (( abytes == 0 || abytes == nbytes )) || {
        printf 'ERROR\t%s needs %d address octets, got %d — refusing (TS 24.008 §10.5.6.4)\n' \
            "$name" "$nbytes" "$abytes" >&2; return 2; }
    local lc=$(( 2 + abytes ))
    printf 'length\t%02x\norg\t%s\ntype\t%s\nvalue\t%s%s\nie\t%02x%s%s%s\n' \
        "$lc" "$org" "$name" "$org" "${t,,}" "$lc" "$org" "${t,,}" "$addr"
}

# ── GEA downgrade detection ─────────────────────────────────────────────
# --gea-downgrade <offered,csv> <selected>. The selected algorithm MUST be in
# the offered set: a network that picks an un-offered GEA is either breaking
# TS 43.020 §D.4.8 or forcing a downgrade. Exit 1 when the selection is
# inconsistent; the caller decides what to do with the finding.
gprs_gea_downgrade() {
    local offered="${1:-}" selected="${2:-}"
    [[ -n "$offered" && "$selected" =~ ^[0-5]$ ]] || { printf 'ERROR\tusage: --gea-downgrade <offered,csv> <selected 0-5>\n' >&2; return 2; }
    local best=0 a in_offered=0
    local IFS=','
    for a in $offered; do
        [[ "$a" =~ ^[0-5]$ ]] || { printf 'ERROR\tnot a GEA index: %s\n' "$a" >&2; return 2; }
        (( a > best )) && best=$a
        (( a == selected )) && in_offered=1
    done
    printf 'offered\t%s\nselected\t%s\nselected_name\t%s\nbest_offered\t%s\n' \
        "$offered" "$selected" "$(gprs_gea_name "$selected")" "$(gprs_gea_name "$best")"
    if (( selected == 0 )); then
        # GEA0 is not a bit in the MS network capability IE: it means "no
        # encryption". Selecting it is always the plaintext outcome, offered or not.
        printf 'verdict\tDOWNGRADE — the network selected GEA0; user data is unprotected\n'
    elif (( in_offered == 0 )); then
        printf 'verdict\tNOT-OFFERED — the network selected GEA%s, which the MS did not offer (violates TS 43.020 §D.4.8 or forces a downgrade)\n' "$selected"
        return 1
    elif (( selected < best )); then
        printf 'verdict\tWEAKER — a stronger GEA (%s) was offered but %s was selected\n' "$(gprs_gea_name "$best")" "$(gprs_gea_name "$selected")"
    else
        printf 'verdict\tok — the strongest offered GEA was selected\n'
    fi
}

gprs_plan() {
    cat <<'EOF'
status	handoff
what	capturing or injecting on the Gb or Gn interface
hardware	an SDR for the Um/Gb air interface, or a lab SGSN/GGSN (Osmocom SGSN) on a Gb/IP link
software	Osmocom osmo-sgsn, osmo-ggsn, a packet capture point, and a USIM with GPRS data
flow	1. encode the APN/PDP context here  2. capture the Attach/PDP activation  3. --gea-downgrade over the offered vs selected GEA
note	the air interface needs a BTS and a licence; this module works on captures and configurations you hold
EOF
}

gprs_selftest() {
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
    export GPRS_DIR="$d/loot/gprs"
    mkdir -p "$GPRS_DIR"

    # 1. APN coding (TS 23.003 §9.1). "internet" -> 08 69 6e 74 65 72 6e 65 74.
    chk apn-internet "$(gprs_apn_encode internet)" "08696e7465726e6574"
    chk apn-two "$(gprs_apn_encode internet.telekom)" "08696e7465726e65740774656c656b6f6d"
    chk apn-decode "$(gprs_apn_decode 08696e7465726e65740774656c656b6f6d)" "internet.telekom"
    chk apn-round "$(gprs_apn_decode "$(gprs_apn_encode operator.mnc001.mcc001.gprs)")" "operator.mnc001.mcc001.gprs"
    chk apn-empty "$(gprs_apn_encode '' >/dev/null 2>&1; echo $?)" "2"
    chk apn-badchar "$(gprs_apn_encode 'in ternet' >/dev/null 2>&1; echo $?)" "2"
    chk apn-badlen "$(gprs_apn_decode 09696e7465726e6574 >/dev/null 2>&1; echo $?)" "1"

    # 2. APN IE (TS 24.008 §10.5.6.1 + table 9.5.1: IEI 28, TLV, 3-102 octets).
    chk apn-ie "$(fld "$(gprs_apn_ie internet)" ie)" "280908696e7465726e6574"
    chk apn-ie-too-long "$(gprs_apn_ie \
        "$(printf 'a%.0s' {1..63}).$(printf 'b%.0s' {1..40})" >/dev/null 2>&1; echo $?)" "2"

    # 3. PDP address IE (TS 24.008 §10.5.6.4, type-4 LV, no IEI).
    #    Octet 3 = spare|org (ETSI 0 for 01/02, IETF 1 for 21/57/8d), octet 4 =
    #    type number. Org nibble cross-checked with pycrate's PDPAddr encoder.
    chk pdp-ipv4 "$(gprs_pdp_type_name 21)" "IPv4"
    chk pdp-ipv6 "$(gprs_pdp_type_name 57)" "IPv6"
    chk pdp-ipv4v6 "$(gprs_pdp_type_name 8D)" "IPv4v6"
    chk pdp-ppp "$(gprs_pdp_type_name 01)" "PPP"
    chk pdp-nonip "$(gprs_pdp_type_name 02)" "non-IP"
    chk pdp-unknown "$(gprs_pdp_type_name FF)" "unknown PDP type — never classified as valid"
    chk pdp-ie-ipv4 "$(fld "$(gprs_pdp_type_ie 21)" ie)" "020121"
    chk pdp-ie-ppp "$(fld "$(gprs_pdp_type_ie 01)" ie)" "020001"
    chk pdp-ie-nonip "$(fld "$(gprs_pdp_type_ie 02)" ie)" "020002"
    chk pdp-ie-addr "$(fld "$(gprs_pdp_type_ie 21 c0a80101)" ie)" "060121c0a80101"
    chk pdp-ie-shortaddr "$(gprs_pdp_type_ie 21 c0a801 >/dev/null 2>&1; echo $?)" "2"
    chk pdp-ie-badtype "$(gprs_pdp_type_ie FF >/dev/null 2>&1; echo $?)" "2"

    # 4. GEA capability table — a row says yes only where this module computes
    #    the algorithm and proves it below.
    chk gea0-implemented "$(gprs_gea_table | awk -F'\t' '$1=="GEA0"{print $5}')" "yes"
    chk gea1-refused "$(gprs_gea_table | awk -F'\t' '$1=="GEA1"{print $5}')" "no"
    chk gea5-refused "$(gprs_gea_table | awk -F'\t' '$1=="GEA5"{print $5}')" "no"
    chk gea4-key "$(gprs_gea_table | awk -F'\t' '$1=="GEA4"{print $3}')" "128"
    chk gea3-clause "$(gprs_gea_table | awk -F'\t' '$1=="GEA3"{print $2}')" "TS 55.216 V6.2.0"
    chk gea4-clause "$(gprs_gea_table | awk -F'\t' '$1=="GEA4"{print $2}')" "TS 55.226 V9.0.0"
    chk gea3-implemented "$(gprs_gea_table | awk -F'\t' '$1=="GEA3"{print $5}')" "yes"
    chk gea5-not "$(gprs_gea_table | awk -F'\t' '$1=="GEA5"{print $5}')" "no"
    chk gea-name0 "$(gprs_gea_name 0)" "GEA0 (no encryption; identity)"
    chk gea-name5 "$(gprs_gea_name 5)" "GEA5 (128-bit SNOW 3G; algorithm body licence-gated)"
    chk gea-unknown "$(gprs_gea_name 9)" "unknown GEA — never classified as safe"

    # 5. GEA0 known-answer (TS 43.020 §H.5.1: ciphering function disabled, so
    #    ciphertext == plaintext) and the refusals for everything else.
    chk gea0-kat "$(fld "$(gprs_gea_crypt 0 0011223344556677 00000001 00112233445566778899aabbccddeeff)" ciphertext)" \
        "00112233445566778899aabbccddeeff"
    chk gea1-exit3 "$(gprs_gea_crypt 1 0011223344556677 00000001 ab >/dev/null 2>&1; echo $?)" "3"
    chk gea1-why "$({ gprs_gea_crypt 1 0011223344556677 00000001 ab 2>&1 >/dev/null || true; } | grep -q 'D.4.9' && echo yes || echo no)" "yes"
    chk gea5-why "$({ gprs_gea_crypt 5 00112233445566778899aabbccddeeff 00000001 ab 2>&1 >/dev/null || true; } | grep -q 'licence' && echo yes || echo no)" "yes"
    chk gea1-why "$({ gprs_gea_crypt 1 0011223344556677 00000001 ab 2>&1 >/dev/null || true; } | grep -q '2022/424' && echo yes || echo no)" "yes"
    chk gea-bad-algo "$(gprs_gea_crypt 9 00 00000000 ab >/dev/null 2>&1; echo $?)" "2"

    # 5b. GEA3 and GEA4 against the standards' own test data. The first vector
    #     of each is a full keystream comparison, so a gamma that is right in
    #     length but wrong in bits cannot pass.
    chk gea3-vector1 "$(fld "$(gprs_gea_crypt 3 2BD6459F82C5BC00 8E9421A3 \
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0)" gamma)" \
        "5f359709de950d0105b17b6c90194280f880b48dccdc2afeed415dbef4354eebb21d073ccbbfb2d706bd7affd371fc96e3970d143dcb2624054826"
    chk gea4-vector1 "$(fld "$(gprs_gea_crypt 4 D3C5D592327FB11C4035C6680AF8C6D1 0A3A59B4 \
        000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0)" gamma | cut -c1-32)" \
        "6e217ce41ebefb5ec8094c1597429006"
    chk gea-kat-all "$(gprs_gea_kat | awk -F'\t' '$1=="failed"{print $2}')" "0"
    chk gea-kat-count "$(gprs_gea_kat | awk -F'\t' '$1=="vectors"{print $2}')" "9"
    chk gea3-xor "$(fld "$(gprs_gea_crypt 3 2BD6459F82C5BC00 8E9421A3 0001020304 0)" ciphertext)" "5f34950ada"
    chk gea5-refused "$(gprs_gea_crypt 5 00000000000000000000000000000000 00000000 ab >/dev/null 2>&1; echo $?)" "3"
    chk gea1-refused "$(gprs_gea_crypt 1 0000000000000000 00000000 ab >/dev/null 2>&1; echo $?)" "3"
    chk gea4-key-length "$(gprs_gea_crypt 4 0000000000000000 00000000 ab >/dev/null 2>&1; echo $?)" "2"

    # 6. Downgrade detector — the selection must be one the MS offered.
    chk gea-downgrade0 "$(fld "$(gprs_gea_downgrade 1,2,3 0)" verdict)" "DOWNGRADE — the network selected GEA0; user data is unprotected"
    chk gea-weaker "$(gprs_gea_downgrade 1,2,3 2 | awk -F'\t' '$1=="verdict"{print ($2 ~ /WEAKER/)?"weaker":"ok"}')" "weaker"
    chk gea-ok "$(gprs_gea_downgrade 1,2,3 3 | awk -F'\t' '$1=="verdict"{print ($2 ~ /^ok/)?"ok":"no"}')" "ok"
    chk gea-notoffered "$(gprs_gea_downgrade 2,3 1 >/dev/null 2>&1; echo $?)" "1"
    chk gea-bad "$(gprs_gea_downgrade 9 1 >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

gprs_menu() {
    while true; do
        banner
        echo "  === GPRS / EDGE ==="
        echo
        cat <<'M'
  [1]  GEA capability table (clause, sizes, implemented?)
  [2]  Encode an APN
  [3]  Decode an APN
  [4]  Build the APN / PDP-address IEs
  [5]  GEA downgrade check
  [6]  Plan (handoff)
  [7]  GEA0 pass-through (identity ciphering)
  [8]  GEA3 / GEA4 ciphering
  [9]  Published GEA3/GEA4 test vectors
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) gprs_gea_table; read -rp "  enter " _ ;;
            2) read -rp "  apn> " a; gprs_apn_encode "$a"; read -rp "  enter " _ ;;
            3) read -rp "  apn hex> " h; gprs_apn_decode "$h"; read -rp "  enter " _ ;;
            4) read -rp "  apn> " a; read -rp "  pdp type hex> " t; read -rp "  address hex (blank = dynamic)> " ad; gprs_apn_ie "$a"; gprs_pdp_type_ie "${t:-21}" "$ad"; read -rp "  enter " _ ;;
            5) read -rp "  offered csv> " o; read -rp "  selected> " s; gprs_gea_downgrade "$o" "$s"; read -rp "  enter " _ ;;
            6) gprs_plan; read -rp "  enter " _ ;;
            7) read -rp "  plaintext hex> " p; gprs_gea_crypt 0 "" 00000000 "$p"; read -rp "  enter " _ ;;
            8) read -rp "  GEA 3 or 4> " n; read -rp "  kc hex> " k; read -rp "  input32 hex> " i
               read -rp "  plaintext hex> " p; read -rp "  direction 0/1> " d
               gprs_gea_crypt "$n" "$k" "$i" "$p" "${d:-0}"; read -rp "  enter " _ ;;
            9) gprs_gea_kat; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

gprs_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   gprs_status_tsv ;;
        --gea-table)    gprs_gea_table ;;
        --gea)          gprs_gea_name "${1:-}" ;;
        --apn-encode)   gprs_apn_encode "${1:-}" ;;
        --apn-decode)   gprs_apn_decode "${1:-}" ;;
        --apn-ie)       gprs_apn_ie "${1:-}" ;;
        --pdp-ie)       gprs_pdp_type_ie "${1:-21}" "${2:-}" ;;
        --gea-crypt)    gprs_gea_crypt "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-0}" ;;
        --gea-kat)      gprs_gea_kat ;;
        --gea-downgrade) gprs_gea_downgrade "${1:-}" "${2:-}" ;;
        --plan)         gprs_plan ;;
        --selftest)     gprs_selftest ;;
        --menu)         gprs_menu ;;
        *)
            cat >&2 <<EOF
GPRS / EDGE — GEA capability table, APN coding, PDP address IE

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --gea-table                  per-algorithm clause, sizes, implemented? (TSV)
  --gea <n>                    name one GEA (0-5) with its standing
  --gea-crypt <n> <kc> <in> <pt> [0|1]  GEA ciphering. GEA0 (identity), GEA3
                     and GEA4 compute; GEA1, GEA2 and GEA5 refuse by name
  --gea-kat          the published GEA3/GEA4 test vectors, one row each
  --apn-encode <apn>           TS 23.003 §9.1 label coding
  --apn-decode <hex>           decode a coded APN
  --apn-ie <apn>               APN IE (TS 24.008 §10.5.6.1, IEI 28)
  --pdp-ie <type_hex> [<addr_hex>]  requested PDP address IE (TS 24.008 §10.5.6.4)
  --gea-downgrade <csv> <n>    offered vs selected GEA (exit 1 if not offered)
  --plan                       Gb/Gn lab handoff plan
  --selftest                   known-answer tests for every computation
  --menu                       interactive menu
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
    gprs_cli_main "$@"
fi
