#!/usr/bin/env bash
# SIM / USIM / eSIM / OTA — ISO-7816 APDU work, USIM file access, OTA SMS
# TAR/SPI parsing, eSIM RSP profile operations.
#
# What this module performs for real (no hardware needed):
#   * ISO-7816-4 command APDU construction (short and extended) and parsing
#   * response APDU SW1/SW2 classification against the real status words
#   * USIM EF access planning: SELECT / READ BINARY / READ RECORD / GET RESPONSE
#   * ICCID and IMSI decode from the BCD record, including the odd-digit case
#   * OTA SMS-DELIVER TPDU parse: TAR, SPI bit fields, KIc/KID key set, counter
#   * eSIM RSP profile metadata (ASN.1) decode and profile-state modelling
#   * SIM authentication vectors: COMP128-1/2/3 (SRES/Kc), Milenage and TUAK
#     (f1..f5*, RES/CK/IK, AUTN assembled from f1/f5) — arithmetic delegated to
#     tools/gsm_crypto.py, asserted against TS 35.208 test set 1 there
#   * SGP.22 v2.2.2 ES9+ HTTP/JSON request builder (initiateAuthentication,
#     authenticateClient, getBoundProfilePackage, cancelSession) as a curl
#     command + body; it builds the request and sends nothing (ES2+/ES10 are
#     not implemented here)
#   * SGP.22 ES8+ TLV builder for the BoundProfilePackage (§2.5.4): BF36 header,
#     BF23 InitialiseSecureChannel (§5.5.1), BF24 ConfigureISDP (§5.5.2), BF25
#     StoreMetadata (§5.5.3), BF26 ReplaceSessionKeys (§5.5.4) and the A0/A1/A2/
#     A3 segment wrappers; the clause that fixes each octet is printed with it
#   * a BPP TLV walker (--es8-parse) and the ES9+ response-body parsers
#     (--es9-response, --es9-notification; §6.5.1.4 and §6.5.2.6..§6.5.2.10)
# The SCP03t protection layer (§2.5.4 -> SGP.02 §2.6.4) and the profile element
# chain (SIMAlliance Profile Package [5]) are NOT built here: SGP.22 does not
# fix those octets, so the builders take them as hex or hand off.
#
# What needs hardware and is therefore written as a PLAN FILE:
#   * talking to a physical UICC          -> PC/SC reader (pcscd + CCID)
#   * writing to a programmable UICC      -> sysmoUSIM-SJS1 / Sysmocom SIM
#   * sending a real OTA SMS              -> SMSC access or an Osmocom testbed
#   * installing a profile on an eUICC    -> eUICC (5.2+) + SM-DP+ test account
# Those paths print `status: handoff` and name the hardware (see sim_plan).
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

MOD_TMP="$TMP_DIR/sim"
SIM_DIR="$LOOT_DIR/sim"
SIM_APDU_LOG="$SIM_DIR/apdus.tsv"
SIM_PLAN_DIR="$SIM_DIR/plans"
mkdir -p "$MOD_TMP" "$SIM_DIR" "$SIM_PLAN_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted. An OTA TPDU, an ATR or a
# reader name can carry a tab and forge an entire row in a consumer that
# splits on tab. Tabs, CR and LF become spaces at the point of output.
sim_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── ISO-7816 status words ───────────────────────────────────────────────
# SW1/SW2 classification per ISO/IEC 7816-4 Annex A and the 3GPP USIM
# profile (TS 31.102). The `6C xx` and `61 xx` families carry a value in
# SW2, so they are matched before the generic SW1 table.
sim_sw_label() {
    local sw="${1:-}"
    sw="${sw// /}"
    sw="${sw^^}"
    [[ "$sw" =~ ^[0-9A-F]{4}$ ]] || { echo "unknown"; return 1; }
    local sw1="${sw:0:2}"
    case "$sw" in
        9000) echo "success" ;;
        61*)  echo "success:${sw:2:2} bytes available (GET RESPONSE)" ;;
        6C*)  echo "error: wrong Le, retry with Le=${sw:2:2}" ;;
        6200) echo "warning: no information given" ;;
        6281) echo "warning: part of returned data may be corrupted" ;;
        6282) echo "warning: end of file reached before reading Le bytes" ;;
        6283) echo "warning: selected file deactivated" ;;
        6284) echo "warning: file control information not formatted" ;;
        6285) echo "warning: selected file in termination state" ;;
        6286) echo "warning: no input data from sensor" ;;
        6300) echo "warning: authentication failed" ;;
        63C*) echo "warning: counter is ${sw:2:2} — PIN blocked after counter 0" ;;
        6400) echo "error: execution error (no precise diagnosis)" ;;
        6401) echo "error: immediate process aborted (non-volatile memory unchanged)" ;;
        6500) echo "error: memory error (no precise diagnosis)" ;;
        6581) echo "error: memory failure, write problem" ;;
        6700) echo "error: wrong length (Lc inconsistent with P1/P2)" ;;
        6800) echo "error: CLA function not supported" ;;
        6881) echo "error: logical channel not supported" ;;
        6882) echo "error: secure messaging not supported" ;;
        6982) echo "error: security status not satisfied (PIN or key required)" ;;
        6983) echo "error: authentication method blocked (PIN/PUK/ADM locked)" ;;
        6984) echo "error: reference data not usable (conditions of use not satisfied)" ;;
        6985) echo "error: conditions of use not satisfied (command not allowed here)" ;;
        6986) echo "error: command not allowed, no EF selected" ;;
        6988) echo "error: SM data objects incorrect" ;;
        6A80) echo "error: incorrect parameters in the command data field" ;;
        6A81) echo "error: function not supported" ;;
        6A82) echo "error: file or application not found" ;;
        6A83) echo "error: record not found" ;;
        6A84) echo "error: not enough memory space in the file" ;;
        6A85) echo "error: Lc inconsistent with TLV structure" ;;
        6A86) echo "error: incorrect P1-P2 parameters" ;;
        6A87) echo "error: Lc inconsistent with P1-P2" ;;
        6A88) echo "error: referenced data or application not found" ;;
        6A89) echo "error: file already exists" ;;
        6A8A) echo "error: DF name already exists" ;;
        6B00) echo "error: wrong parameters P1-P2 (offset outside EF)" ;;
        6D00) echo "error: instruction code not supported or invalid" ;;
        6E00) echo "error: class not supported" ;;
        6F00) echo "error: no precise diagnosis" ;;
        *)    case "$sw1" in
                  61) echo "success:${sw:2:2} bytes available (GET RESPONSE)" ;;
                  62) echo "warning: SW1=62, state of non-volatile memory unchanged" ;;
                  63) echo "warning: SW1=63, state of non-volatile memory changed" ;;
                  64) echo "error: SW1=64, execution error" ;;
                  65) echo "error: SW1=65, memory error" ;;
                  67) echo "error: SW1=67, wrong length" ;;
                  68) echo "error: SW1=68, CLA function not supported" ;;
                  69) echo "error: SW1=69, command not allowed" ;;
                  6A) echo "error: SW1=6A, wrong parameters P1-P2" ;;
                  6B) echo "error: SW1=6B, wrong parameters P1-P2" ;;
                  6C) echo "error: SW1=6C, wrong Le" ;;
                  6D) echo "error: SW1=6D, INS not supported" ;;
                  6E) echo "error: SW1=6E, CLA not supported" ;;
                  6F) echo "error: SW1=6F, no precise diagnosis" ;;
                  *)  echo "unknown" ;;
              esac ;;
    esac
}

# Does this status word mean the command succeeded?
sim_sw_ok() {
    local sw; sw="${1// /}"; sw="${sw^^}"
    [[ "$sw" == "9000" || "$sw" == 61* || "$sw" == "6282" ]] && return 0
    return 1
}

# A residual byte count carried in SW2 of the `6C xx` / `61 xx` families.
# Anything else is reported as `-` so no caller mistakes a 00 for a length.
sim_sw_len() {
    local sw; sw="${1// /}"; sw="${sw^^}"
    case "$sw" in
        61*|6C*) printf '%d\n' "$(( 16#${sw:2:2} ))" ;;
        *)       printf -- '-\n' ;;
    esac
}

# ── ISIM/USIM file id table ─────────────────────────────────────────────
# 3GPP TS 31.102 (USIM) and TS 51.011 (SIM) file identifiers, plus the
# GSM 11.11 DF layout that a 2G-only card still exposes. `sim_file_name`
# prints `<name>|<type>|<spec>`; the pipe keeps the fields apart because
# the names themselves contain spaces.
sim_file_name() {
    case "${1^^}" in
        3F00) echo "MF (master file)|MF|ISO 7816-4 / TS 31.102" ;;
        3F01) echo "DF_TELECOM|DF|ISO 7816-4" ;;
        3F02) echo "DF_GSM (2G directory)|DF|TS 51.011" ;;
        7F10) echo "DF_TELECOM|DF|ISO 7816-4" ;;
        7F20) echo "DF_GSM|DF|TS 51.011" ;;
        7F21) echo "DF_DCS1800|DF|TS 51.011" ;;
        7F22) echo "DF_IS-41|DF|TS 51.011" ;;
        7F23) echo "DF_FP-CTS|DF|TS 51.011" ;;
        7F25) echo "DF_TELECOM (GSM)|DF|TS 51.011" ;;
        7FFF) echo "ADF_USIM|ADF|TS 31.102" ;;
        7FF2) echo "DF_5GS|DF|TS 31.102" ;;
        5FC0) echo "DF_GSM access (5G)|DF|TS 31.102" ;;
        2FE2) echo "EF_ICCID|EF transparent|TS 51.011 / TS 31.102" ;;
        2F00) echo "EF_ADN (GSM)|EF linear fixed|TS 51.011" ;;
        2F05) echo "EF_MSISDN (GSM)|EF linear fixed|TS 51.011" ;;
        2F06) echo "EF_SMS (GSM)|EF linear fixed|TS 51.011" ;;
        2F07) echo "EF_SPN (GSM)|EF transparent|TS 51.011" ;;
        2F08) echo "EF_Kc (GSM)|EF transparent|TS 51.011" ;;
        2FE0) echo "EF_ACMmax|EF transparent|TS 51.011" ;;
        6F05) echo "EF_LI (language indication)|EF transparent|TS 31.102" ;;
        6F07) echo "EF_IMSI|EF transparent|TS 31.102" ;;
        6F08) echo "EF_KEYS (Ciphering and Integrity Keys)|EF transparent|TS 31.102" ;;
        6F09) echo "EF_KEYSPS|EF transparent|TS 31.102" ;;
        6F0B) echo "EF_FDN|EF linear fixed|TS 31.102" ;;
        6F20) echo "EF_Kc (GSM ciphering key)|EF transparent|TS 31.102" ;;
        6F31) echo "EF_HPPLMN (HPLMN search period)|EF transparent|TS 31.102" ;;
        6F37) echo "EF_ACMmax|EF transparent|TS 31.102" ;;
        6F38) echo "EF_UST (USIM Service Table)|EF transparent|TS 31.102" ;;
        6F39) echo "EF_ACM|EF cyclic|TS 31.102" ;;
        6F3B) echo "EF_FDN|EF linear fixed|TS 31.102" ;;
        6F3C) echo "EF_CCP1|EF transparent|TS 31.102" ;;
        6F3E) echo "EF_GID1|EF transparent|TS 31.102" ;;
        6F41) echo "EF_PUCT|EF transparent|TS 31.102" ;;
        6F42) echo "EF_CBMI|EF transparent|TS 31.102" ;;
        6F43) echo "EF_ACC|EF transparent|TS 31.102" ;;
        6F44) echo "EF_FPLMN|EF linear fixed|TS 31.102" ;;
        6F46) echo "EF_SPN (Service Provider Name)|EF transparent|TS 31.102" ;;
        6F47) echo "EF_SMS (SMS storage)|EF linear fixed|TS 31.102" ;;
        6F48) echo "EF_SMSR|EF transparent|TS 31.102" ;;
        6F4D) echo "EF_SMSP (SMS parameters)|EF linear fixed|TS 31.102" ;;
        6F50) echo "EF_BCCH|EF transparent|TS 31.102" ;;
        6F56) echo "EF_EST|EF transparent|TS 31.102" ;;
        6F5B) echo "EF_START-HFN|EF transparent|TS 31.102" ;;
        6F5C) echo "EF_THRESHOLD|EF transparent|TS 31.102" ;;
        6F60) echo "EF_PLMNwAct|EF linear fixed|TS 31.102" ;;
        6F61) echo "EF_OPLMNwAct|EF linear fixed|TS 31.102" ;;
        6F62) echo "EF_HPLMNwAct|EF linear fixed|TS 31.102" ;;
        6F73) echo "EF_AD (Administrative Data)|EF transparent|TS 31.102" ;;
        6F78) echo "EF_ARR|EF linear fixed|TS 31.102" ;;
        6F7B) echo "EF_FPLMN (forbidden PLMN)|EF linear fixed|TS 31.102" ;;
        6F7E) echo "EF_LOCI (Location Information)|EF transparent|TS 31.102" ;;
        6F7F) echo "EF_ADN (USIM)|EF linear fixed|TS 31.102" ;;
        6F80) echo "EF_ICCID|EF transparent|TS 31.102" ;;
        6F81) echo "EF_ACC|EF transparent|TS 31.102" ;;
        6F82) echo "EF_IMSI (2G alias)|EF transparent|TS 31.102" ;;
        6F87) echo "EF_EPRLOCI|EF transparent|TS 31.102" ;;
        6F8B) echo "EF_PSLOCI (Packet Switched LOCI)|EF transparent|TS 31.102" ;;
        6F91) echo "EF_PLMNsel|EF transparent|TS 31.102" ;;
        6F92) echo "EF_SMSS|EF transparent|TS 31.102" ;;
        6F98) echo "EF_MSISDN (USIM)|EF linear fixed|TS 31.102" ;;
        6FA0) echo "EF_PNN|EF linear fixed|TS 31.102" ;;
        6FB1) echo "EF_OPL|EF linear fixed|TS 31.102" ;;
        6FB5) echo "EF_EPSLOCI (EPS LOCI)|EF transparent|TS 31.102" ;;
        6FB7) echo "EF_EPSNSC|EF transparent|TS 31.102" ;;
        6FC4) echo "EF_5GSNSC|EF transparent|TS 31.102" ;;
        6FAD) echo "EF_AD (Administrative Data)|EF transparent|TS 31.102" ;;
        6FE3) echo "EF_ICCID_wrapper|EF transparent|TS 31.102" ;;
        4F20) echo "DF_GSM (for ISIM context)|DF|TS 31.103" ;;
        *)    echo "unknown EF/DF|unknown|—" ;;
    esac
}

# Full path of an EF under a DF, for SELECT-by-path planning.
sim_file_path() {
    case "${1^^}" in
        3F00|7F20|7F10|7FFF|7FF2) printf '%s\n' "${1^^}" ;;
        2FE2|2F05|2F07|2F08|2F00|2F06) printf '3F00/7F20/%s\n' "${1^^}" ;;
        *) printf '3F00/7FFF/%s\n' "${1^^}" ;;
    esac
}

# ── hex helpers ─────────────────────────────────────────────────────────
sim_is_hex() { [[ "${1:-}" =~ ^[0-9a-fA-F]*$ ]] && (( ${#1} % 2 == 0 )); }
sim_norm_hex() { printf '%s' "${1// /}" | tr 'a-f' 'A-F'; }

sim_hex_bytes() { printf '%d\n' "$(( ${#1} / 2 ))"; }

# printf '%02X' pads but never truncates, so a value above 0xFF would emit
# three hex digits and silently corrupt every APDU it is spliced into.
# Every hex byte this module emits goes through sim_byte.
sim_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

# Same trap one width up: '%04X' emits five digits for 65536, so the
# extended Le/Lc fields are always masked before formatting.
sim_word() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }

# hex string -> decimal. Accepts any byte length: Bash rejects an empty
# operand and the whole string must be a valid hex literal, so validate
# first and report the failure instead of leaking an arithmetic error.
sim_hex_dec() {
    local h="${1// /}"
    [[ -n "$h" && "$h" =~ ^[0-9a-fA-F]+$ ]] || { printf '0\n'; return 1; }
    local n; n=$(sim_hex_bytes "$h")
    (( n * 2 == ${#h} )) || { printf '0\n'; return 1; }
    local v=0 i
    for (( i = 0; i < ${#h}; i++ )); do
        v=$(( (v << 4) | 16#${h:$i:1} ))
    done
    printf '%d\n' "$v"
}

# ── APDU construction (ISO/IEC 7816-4 §5) ───────────────────────────────
# Case 1      CLA INS P1 P2                        (no data, no response)
# Case 2S     CLA INS P1 P2 Le                     (short Le, 1 byte)
# Case 2E     CLA INS P1 P2 00 Le(2)               (extended Le)
# Case 3S     CLA INS P1 P2 Lc Data
# Case 3E     CLA INS P1 P2 00 Lc(2) Data
# Case 4S     CLA INS P1 P2 Lc Data Le
# Case 4E     CLA INS P1 P2 00 Lc(2) Data Le(2)
#
# Output TSV: apdu_hex  case  cla ins p1 p2 lc le extended  length
sim_build_apdu() {
    local cla="${1:-}" ins="${2:-}" p1="${3:-}" p2="${4:-}"
    local data="${5:-}" le="${6:-}"
    cla="${cla// /}"; ins="${ins// /}"; p1="${p1// /}"; p2="${p2// /}"
    data="${data// /}"; le="${le// /}"
    [[ "$cla" =~ ^[0-9a-fA-F]{1,2}$ ]] || { printf 'ERROR\tCLA must be 1-2 hex digits\n' >&2; return 2; }
    [[ "$ins" =~ ^[0-9a-fA-F]{1,2}$ ]] || { printf 'ERROR\tINS must be 1-2 hex digits\n' >&2; return 2; }
    [[ "$p1"  =~ ^[0-9a-fA-F]{1,2}$ ]] || { printf 'ERROR\tP1 must be 1-2 hex digits\n'  >&2; return 2; }
    [[ "$p2"  =~ ^[0-9a-fA-F]{1,2}$ ]] || { printf 'ERROR\tP2 must be 1-2 hex digits\n'  >&2; return 2; }
    if [[ -n "$data" ]]; then
        sim_is_hex "$data" || { printf 'ERROR\tdata must be an even-length hex string\n' >&2; return 2; }
    fi
    if [[ -n "$le" ]]; then
        [[ "$le" =~ ^[0-9a-fA-F]{1,4}$ ]] || { printf 'ERROR\tLe must be 1-4 hex digits\n' >&2; return 2; }
    fi
    cla=$(sim_byte "$(( 16#$cla ))"); ins=$(sim_byte "$(( 16#$ins ))")
    p1=$(sim_byte  "$(( 16#$p1  ))"); p2=$(sim_byte  "$(( 16#$p2  ))")

    local lc=0 have_data=0
    if [[ -n "$data" ]]; then have_data=1; lc=$(sim_hex_bytes "$data"); fi

    # Extended is mandatory when Lc or Le will not fit one byte, and may be
    # requested explicitly by giving Le as 4 hex digits (0000 = 65536).
    local extended=0
    (( lc > 255 )) && extended=1
    [[ "$le" =~ ^[0-9a-fA-F]{4}$ ]] && extended=1
    [[ -n "$le" && "$le" =~ ^[0-9a-fA-F]{1,4}$ ]] && (( 16#$le > 256 )) && extended=1

    local body="$cla$ins$p1$p2" case="1" le_out="-"
    if (( extended )); then
        if (( have_data )); then
            case="3E"; body+=$(sim_byte 00)$(sim_word "$lc")$data
            if [[ -n "$le" ]]; then
                case="4E"
                local v4=$(( 16#$le )); (( v4 == 0 )) && v4=65536
                body+=$(sim_word "$v4"); le_out="$v4"
            fi
        else
            if [[ -n "$le" ]]; then
                case="2E"
                local v=$(( 16#$le )); (( v == 0 )) && v=65536
                body+=$(sim_byte 00)$(sim_word "$v"); le_out="$v"
            else
                case="1"
            fi
        fi
    else
        if (( have_data )); then
            case="3S"; body+=$(printf '%02X%s' "$lc" "$data")
            if [[ -n "$le" ]]; then
                case="4S"
                local v=$(( 16#$le )); (( v == 0 )) && v=256
                body+=$(sim_byte "$v"); le_out="$v"
            fi
        else
            if [[ -n "$le" ]]; then
                case="2S"
                local v=$(( 16#$le )); (( v == 0 )) && v=256
                body+=$(sim_byte "$v"); le_out="$v"
            else
                case="1"
            fi
        fi
    fi
    printf 'apdu_hex\t%s\ncase\t%s\ncla\t%s\nins\t%s\np1\t%s\np2\t%s\nlc\t%s\nle\t%s\nextended\t%s\nlength\t%s\n' \
        "$body" "$case" "$cla" "$ins" "$p1" "$p2" "$lc" "$le_out" \
        "$([[ $extended -eq 1 ]] && echo yes || echo no)" "$(sim_hex_bytes "$body")"
}

# Parse a command APDU written as one hex string. Returns non-zero when the
# byte string cannot be a valid ISO-7816-4 command APDU at all.
sim_parse_capdu() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 4 )) || { printf 'ERROR\tAPDU too short (%d bytes, minimum 4)\n' "$n" >&2; return 1; }

    local cla="${h:0:2}" ins="${h:2:2}" p1="${h:4:2}" p2="${h:6:2}"
    local pos=8 lc=0 le="-" case="1" extended="no" data=""
    local b1 b2
    if (( n == 4 )); then
        case="1"
    elif (( n == 5 )); then
        # Case 2S: a single Le byte.
        case="2S"; le=$(sim_hex_dec "${h:8:2}")
        (( le == 0 )) && le=256
    elif (( n >= 7 )) && [[ "${h:8:2}" == "00" ]]; then
        # Either Case 2E/3E/4E (00 || Lc/Le hi || lo) — or a short Case 3S
        # whose Lc really is 0x00, which is impossible with a data field, so
        # a leading 00 followed by two bytes is always the extended form.
        b1=$(sim_hex_dec "${h:10:2}"); b2=$(sim_hex_dec "${h:12:2}")
        local ext_val=$(( b1 * 256 + b2 ))
        extended="yes"
        if (( n == 7 )); then
            case="2E"; le="$ext_val"; (( le == 0 )) && le=65536
        else
            lc="$ext_val"
            local rest=$(( n - 7 ))
            if (( lc == 0 )); then
                printf 'ERROR\textended APDU declares Lc=0 with %d trailing bytes\n' "$rest" >&2
                return 1
            fi
            if (( rest == lc )); then
                case="3E"; data="${h:14}"
            elif (( rest == lc + 2 )); then
                case="4E"; data="${h:14:$(( lc * 2 ))}"
                le=$(sim_hex_dec "${h:$(( 14 + lc * 2 )):4}")
            else
                printf 'ERROR\tlength mismatch: Lc=%d but %d trailing bytes (want %d or %d)\n' \
                    "$lc" "$rest" "$lc" "$(( lc + 2 ))" >&2
                return 1
            fi
        fi
    else
        # Case 3S or 4S: Lc is the byte after the header.
        lc=$(sim_hex_dec "${h:8:2}")
        local rest=$(( n - 5 ))
        if (( lc == 0 )); then
            printf 'ERROR\tLc=0 with %d trailing bytes is not a valid short APDU\n' "$rest" >&2
            return 1
        fi
        if (( rest == lc )); then
            case="3S"; data="${h:10}"
        elif (( rest == lc + 1 )); then
            case="4S"; data="${h:10:$(( lc * 2 ))}"
            le=$(sim_hex_dec "${h:$(( 10 + lc * 2 )):2}")
            (( le == 0 )) && le=256
        else
            printf 'ERROR\tlength mismatch: Lc=%d but %d data bytes present\n' "$lc" "$rest" >&2
            return 1
        fi
    fi
    printf 'apdu_hex\t%s\ncase\t%s\ncla\t%s\nins\t%s\np1\t%s\np2\t%s\nlc\t%s\nle\t%s\nextended\t%s\nlength\t%s\ndata\t%s\n' \
        "$h" "$case" "$cla" "$ins" "$p1" "$p2" "$lc" "$le" "$extended" "$n" "$data"
}

# Parse a response APDU: the trailing SW1/SW2 plus whatever data preceded it.
sim_parse_rapdu() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 2 )) || { printf 'ERROR\tresponse APDU too short (%d bytes, need SW1 SW2)\n' "$n" >&2; return 1; }
    local sw="${h:$(( (n - 2) * 2 )):4}"
    local data="${h:0:$(( (n - 2) * 2 ))}"
    printf 'sw\t%s\nsw1\t%s\nsw2\t%s\nstatus\t%s\nlength_byte\t%s\ndata\t%s\ndata_len\t%s\n' \
        "$sw" "${sw:0:2}" "${sw:2:2}" "$(sim_sw_label "$sw")" "$(sim_sw_len "$sw")" \
        "$data" "$(sim_hex_bytes "$data")"
}

# ── USIM command builders (ISO 7816-4 §7 + TS 31.102 §7) ────────────────
# SELECT by file identifier:  A0 A4 00 00 02 <fid>
sim_apdu_select_fid() {
    local fid="${1// /}"
    [[ "$fid" =~ ^[0-9a-fA-F]{4}$ ]] || { printf 'ERROR\tfile id must be 4 hex digits\n' >&2; return 2; }
    sim_build_apdu A0 A4 00 00 "$(sim_norm_hex "$fid")"
}

# SELECT by path from the MF: A0 A4 08 00 <Lc> <fid...>
sim_apdu_select_path() {
    local path="${1// /}" p="${1// /}" data="" n=0
    path="${path//-/}"
    path="${path//\//}"
    [[ "$path" =~ ^([0-9a-fA-F]{4})+$ ]] || { printf 'ERROR\tpath must be 4-hex-digit file ids, e.g. 3F00/7F20/6F07\n' >&2; return 2; }
    while (( n < ${#path} )); do data+="${path:$n:4}"; n=$(( n + 4 )); done
    sim_build_apdu A0 A4 08 00 "$data"
}

# READ BINARY: A0 B0 <offset hi> <offset lo> <Le>
sim_apdu_read_binary() {
    local off="${1:-0}" le="${2:-0}"
    [[ "$off" =~ ^[0-9]+$ ]] || { printf 'ERROR\toffset must be decimal\n' >&2; return 2; }
    [[ "$le"  =~ ^[0-9]+$ ]] || { printf 'ERROR\tLe must be decimal\n' >&2; return 2; }
    (( off <= 32767 )) || { printf 'ERROR\toffset %s out of range (0..32767 with P1 bit8=0)\n' "$off" >&2; return 1; }
    (( le >= 1 && le <= 256 )) || { printf 'ERROR\tLe must be 1..256\n' >&2; return 1; }
    local v=$(( le % 65536 )); (( le == 256 )) && v=0
    sim_build_apdu A0 B0 "$(sim_byte "$(( off / 256 ))")" "$(sim_byte "$(( off % 256 ))")" "" "$(sim_byte "$v")"
}

# READ RECORD: A0 B2 <record> <mode> <Le>   (mode 04 = absolute/EF, 02 = next)
sim_apdu_read_record() {
    local rec="${1:-1}" mode="${2:-04}" le="${3:-0}"
    [[ "$rec" =~ ^[0-9]+$ ]] || { printf 'ERROR\trecord number must be decimal\n' >&2; return 2; }
    [[ "$mode" =~ ^[0-9a-fA-F]{2}$ ]] || { printf 'ERROR\tmode must be 2 hex digits (04 absolute, 02 next)\n' >&2; return 2; }
    [[ "$le"  =~ ^[0-9]+$ ]] || { printf 'ERROR\tLe must be decimal\n' >&2; return 2; }
    (( rec >= 1 && rec <= 254 )) || { printf 'ERROR\trecord number must be 1..254\n' >&2; return 1; }
    (( le >= 1 && le <= 256 )) || { printf 'ERROR\tLe must be 1..256\n' >&2; return 1; }
    local v=$(( le % 65536 )); (( le == 256 )) && v=0
    sim_build_apdu A0 B2 "$(sim_byte "$rec")" "${mode^^}" "" "$(sim_byte "$v")"
}

# GET RESPONSE: A0 C0 00 00 <Le>
sim_apdu_get_response() {
    local le="${1:-0}"
    [[ "$le" =~ ^[0-9]+$ ]] || { printf 'ERROR\tLe must be decimal\n' >&2; return 2; }
    (( le >= 1 && le <= 256 )) || { printf 'ERROR\tLe must be 1..256\n' >&2; return 1; }
    local v=$(( le % 65536 )); (( le == 256 )) && v=0
    sim_build_apdu A0 C0 00 00 "" "$(sim_byte "$v")"
}

# ── BCD codecs (TS 31.102 §4.2.1 / §4.2.2) ──────────────────────────────
# Both records are plain BCD with the nibbles swapped inside every byte, and
# both were read with an invented extra field: EF_ICCID was given a "0x98
# marker" octet to skip, EF_IMSI no parity nibble to strip. Every record
# therefore lost (ICCID) or gained (IMSI) a leading character, and the fields
# that follow a shifted digit -- the country, the MCC -- came out plausible
# and wrong. The two codecs below read what the clause says is there.
sim_luhn_ok() {
    local s="${1:-}" i d sum=0 dbl=0
    case "$s" in ''|*[!0-9]*) return 1 ;; esac
    for (( i = ${#s} - 1; i >= 0; i-- )); do
        d="${s:i:1}"
        if (( dbl )); then
            d=$(( d * 2 ))
            (( d > 9 )) && d=$(( d - 9 ))
        fi
        sum=$(( sum + d ))
        dbl=$(( 1 - dbl ))
    done
    (( sum % 10 == 0 ))
}

# The number plan is ITU-T E.118's, not the PLMN's: the leading two digits are
# the Issuer Identification Number ("89" for telecommunications), then a
# country calling code of one to three digits, then the issuer's own numbering.
# The split is not self-describing, so the code is matched against this table
# and reported unknown otherwise. The digit after "89" is a country calling
# code -- 8986... is China (+86), not MCC 860.
sim_icc_calling_code() {
    local d="${1:-}" p3="${1:0:3}" p2="${1:0:2}" p1="${1:0:1}"
    case "$p3" in
        212) echo "212|Morocco" ;;       351) echo "351|Portugal" ;;
        380) echo "380|Ukraine" ;;       420) echo "420|Czechia" ;;
        966) echo "966|Saudi Arabia" ;;  971) echo "971|United Arab Emirates" ;;
        972) echo "972|Israel" ;;
        *)
            case "$p2" in
                20) echo "20|Egypt" ;;    27) echo "27|South Africa" ;;
                33) echo "33|France" ;;   34) echo "34|Spain" ;;
                39) echo "39|Italy" ;;    44) echo "44|United Kingdom" ;;
                49) echo "49|Germany" ;;  52) echo "52|Mexico" ;;
                55) echo "55|Brazil" ;;   61) echo "61|Australia" ;;
                62) echo "62|Indonesia" ;; 65) echo "65|Singapore" ;;
                66) echo "66|Thailand" ;; 81) echo "81|Japan" ;;
                82) echo "82|South Korea" ;; 84) echo "84|Vietnam" ;;
                86) echo "86|China" ;;    90) echo "90|Turkey" ;;
                91) echo "91|India" ;;    92) echo "92|Pakistan" ;;
                98) echo "98|Iran" ;;
                *)
                    case "$p1" in
                        1) echo "1|United States / Canada" ;;
                        7) echo "7|Russia / Kazakhstan" ;;
                        *) echo "unknown|unknown" ;;
                    esac ;;
            esac ;;
    esac
}

sim_decode_iccid() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 2 )) || { printf 'ERROR\tICCID record too short (%d bytes)\n' "$n" >&2; return 1; }

    # Every octet is two digits, low nibble first. Nothing is skipped: the
    # 0x98 that opens most records is the digits 8 and 9.
    local digits="" i
    for (( i = 0; i < n; i++ )); do
        local b="${h:$(( i * 2 )):2}"
        digits+="${b:1:1}${b:0:1}"
    done
    [[ "$digits" =~ ^[0-9]*[Ff]?$ ]] || { printf 'ERROR\tICCID nibbles are not all decimal: %s\n' "$digits" >&2; return 1; }
    # The filler is the high nibble of the last octet and nothing else, so it
    # is a trailing character after the swap. An F anywhere else stays put and
    # the record is refused above.
    local filler="no"
    if [[ "$digits" == *[Ff] ]]; then filler="yes"; digits="${digits%[Ff]}"; fi
    (( ${#digits} >= 4 )) || { printf 'ERROR\tdecoded ICCID too short (%d digits)\n' "${#digits}" >&2; return 1; }

    local issuer="${digits:0:2}" check="-" luhn="n/a" cc="-" country="-"
    case "${#digits}" in
        19|20)  check="${digits: -1}"
                if sim_luhn_ok "$digits"; then luhn="valid"; else luhn="INVALID"; fi ;;
        *)      luhn="absent (${#digits} digits, the check digit brings it to 19 or 20)" ;;
    esac
    if [[ "$issuer" == "89" ]]; then
        cc=$(sim_icc_calling_code "${digits:2}")
        country="${cc#*|}"; cc="${cc%%|*}"
    fi
    printf 'iccid\t%s\nlength\t%d\nissuer\t%s\ncalling_code\t%s\ncountry\t%s\nfiller\t%s\ncheck_digit\t%s\nluhn\t%s\n' \
        "$digits" "${#digits}" "$issuer" "$cc" "$country" "$filler" "$check" "$luhn"
}

# IMSI -> BCD for EF_IMSI. Standard GSM packing (TS 23.003 §2.3): two digits
# per octet, the first digit in the LOW nibble, and an F filler in the high
# nibble when the count is odd. --selftest cross-checks this against
# `09_lte_attach --imsi-encode`, which is the module that owns the NAS form.
sim_bcd_encode() {  # <digits> -> packed hex
    local d="${1:-}"
    [[ "$d" =~ ^[0-9]{14,15}$ ]] || return 1
    local out="" i nib
    for (( i = 0; i < ${#d}; i += 2 )); do
        nib="${d:i:1}"
        if (( i + 1 < ${#d} )); then
            out+="${d:i+1:1}${nib}"
        else
            out+="F${nib}"
        fi
    done
    printf '%s' "$out"
}

sim_decode_imsi() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 2 )) || { printf 'ERROR\tIMSI record too short (%d bytes)\n' "$n" >&2; return 1; }

    local len_byte="" body="$h"
    if [[ "$h" == +* ]]; then
        body="${h#+}"
    else
        # A first byte of 1..9 with octets behind it is the length byte; L
        # reaches 9 for an even digit count (the parity nibble plus sixteen
        # digits), not the 1..8 a sixteen-digit ceiling suggests. A record
        # whose octet count disagrees with its own length byte is still read,
        # and said to disagree: encoders in the wild pad past their own count.
        local first; first=$(sim_hex_dec "${h:0:2}")
        if (( first >= 1 && first <= 9 && first + 1 <= n )); then
            len_byte="$first"; body="${h:2}"
        fi
    fi
    local bn; bn=$(sim_hex_bytes "$body")
    local swapped="" i
    for (( i = 0; i < bn; i++ )); do
        local b="${body:$(( i * 2 )):2}"
        swapped+="${b:1:1}${b:0:1}"
    done

    # The octet after the length byte carries the parity of the digit count in
    # its low nibble (1 even, 9 odd) and the first IMSI digit in its high one,
    # so after the swap the parity is the leading character. Reading it as a
    # digit turned the IMSI 310260123456789 into 9310260123456789 -- MCC 931
    # and "unknown" where the card says Vodafone US.
    local indicator="${swapped:0:1}" rest="${swapped:1}" parity
    case "$indicator" in
        1) parity="even" ;;
        9) parity="odd" ;;
        *) printf 'ERROR\tparity indicator "%s" is neither 1 (even digit count) nor 9 (odd); this is not an EF_IMSI body\n' "$indicator" >&2; return 1 ;;
    esac
    local filler="none"
    while [[ "$rest" == *[Ff] ]]; do filler="F"; rest="${rest%[Ff]}"; done
    [[ "$rest" =~ ^[0-9]+$ ]] || { printf 'ERROR\tIMSI digits are not all decimal: %s\n' "$rest" >&2; return 1; }
    local digits="$rest"
    (( ${#digits} >= 5 )) || { printf 'ERROR\tdecoded IMSI too short (%d digits)\n' "${#digits}" >&2; return 1; }
    (( ${#digits} <= 15 )) || { printf 'ERROR\tIMSI has %d digits, more than the 15 an IMSI can have\n' "${#digits}" >&2; return 1; }

    local length_agrees="n/a"
    if [[ -n "$len_byte" ]]; then
        if (( bn == len_byte )); then length_agrees="yes"; else length_agrees="no"; fi
    fi

    local parity_agrees="yes"
    if [[ "$parity" == "odd" ]]; then
        (( ${#digits} % 2 == 1 )) || parity_agrees="no"
    else
        (( ${#digits} % 2 == 0 )) || parity_agrees="no"
    fi
    local mcc="${digits:0:3}" mnc2="${digits:3:2}" mnc3="${digits:3:3}"
    local hplmn2="${mcc}-${mnc2}" hplmn3="${mcc}-${mnc3}"
    printf 'imsi\t%s\nlength\t%d\nlength_byte\t%s\nbody_bytes\t%d\nlength_agrees\t%s\nparity\t%s\nparity_agrees\t%s\nfiller\t%s\nmcc\t%s\nmnc_2digit\t%s\nmnc_3digit\t%s\nhplmn_2digit\t%s\nhplmn_3digit\t%s\ncountry\t%s\nmsin\t%s\n' \
        "$digits" "${#digits}" "$([[ -n "$len_byte" ]] && echo "$len_byte" || echo none)" \
        "$bn" "$length_agrees" "$parity" "$parity_agrees" "$filler" \
        "$mcc" "$mnc2" "$mnc3" "$hplmn2" "$hplmn3" \
        "$(sim_mcc_country "$mcc")" "${digits:5}"
}

# MCC -> country. Compact table; unknown is the honest answer.
sim_mcc_country() {
    case "${1:-}" in
        208) echo "France" ;;     262) echo "Germany" ;;
        234|235) echo "United Kingdom" ;;
        310|311|312|313|314|315|316) echo "United States" ;;
        204) echo "Netherlands" ;; 214) echo "Spain" ;;
        222) echo "Italy" ;;       228) echo "Switzerland" ;;
        505) echo "Australia" ;;   440|441) echo "Japan" ;;
        450) echo "South Korea" ;; 460) echo "China" ;;
        404|405|406) echo "India" ;; 724) echo "Brazil" ;;
        302) echo "Canada" ;;      530) echo "New Zealand" ;;
        232) echo "Austria" ;;     240|242|244|246|248) echo "Nordics" ;;
        206) echo "Belgium" ;;     268) echo "Portugal" ;;
        202) echo "Greece" ;;      286) echo "Turkey" ;;
        250) echo "Russia" ;;      510) echo "Indonesia" ;;
        *)   echo "unknown" ;;
    esac
}

# ── EF_AD: administrative data (TS 31.102 §4.2.18, ETSI TS 131 102) ─────
# File size 4+X, transparent, 4 mandatory bytes:
#   Byte 1     UE operation mode
#   Bytes 2-3  additional information (meaning depends on byte 1)
#   Byte 4     length of the MNC in the IMSI (bits b1-b4, value 2 or 3)
#   Bytes 5..  RFU
#
# Byte 1 mode coding, verbatim from the spec:
#   '00' normal operation          '80' type approval operations
#   '01' normal + specific fac.    '81' type approval + specific fac.
#   '02' maintenance (off line)    '04' cell test operation
# b1 of byte 1 (bit 0x01) is the "specific facilities" selector: when it is
# set, bytes 2-3 carry the facility bits below instead of vendor data.
#
# The PIN enable flags live in EF_AD only in the 2G (TS 51.011) variant;
# in the USIM the PIN states are card state, readable from the card's
# status/ATR history, and EF_AD byte 3 b1 is the CIPHERING INDICATOR. The
# decoder therefore reports the USIM reading and names the 2G alternative
# rather than inventing PIN flags the USIM file does not carry.
sim_parse_ef_ad() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 4 )) || { printf 'ERROR\tEF_AD must be at least 4 bytes (got %d)\n' "$n" >&2; return 1; }

    local b1="${h:0:2}" mode; mode=$(sim_hex_dec "$b1")
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
    local specific="no"
    (( mode & 0x01 )) && specific="yes"

    local mnc_bits=$(( 16#${h:6:2} & 0x0F ))
    local mnc_len="$mnc_bits"
    case "$mnc_bits" in
        2|3) ;;
        *)   mnc_len="${mnc_bits} (reserved — only 2 and 3 are specified)" ;;
    esac

    local b2="${h:2:2}" b3="${h:4:2}" extra=$(( n - 4 ))
    local ciphering="n/a" csg="n/a" prose="n/a" edrx="n/a"
    if [[ "$specific" == "yes" ]]; then
        local w3=$(( 16#$b3 ))
        ciphering=$([[ $(( w3 & 0x01 )) -ne 0 ]] && echo "enabled (ciphering indicator shown to the user)" || echo "disabled (ciphering indicator not shown)")
        csg=$([[ $(( w3 & 0x02 )) -ne 0 ]] && echo "operator CSG list only" || echo "all available CSGs may be displayed")
        prose=$([[ $(( w3 & 0x04 )) -ne 0 ]] && echo "authorised for ProSe Public Safety without the ProSe Function" || echo "not authorised for ProSe Public Safety")
        edrx=$([[ $(( w3 & 0x08 )) -ne 0 ]] && echo "ME may modify the UICC polling interval / disable the interface in eDRX" || echo "ME may not modify polling or disable the interface in eDRX")
    else
        b3="(manufacturer specific — operation mode does not set b1)"
    fi

    printf 'raw\t%s\nbytes\t%s\nbyte1\t%s\nmode\t%s\nmode_code\t%s\nspecific_facilities\t%s\nbyte2\t%s\nbyte3\t%s\nb3_ciphering_indicator\t%s\nb3_csg_display\t%s\nb3_prose_public_safety\t%s\nb3_extended_drx\t%s\nmnc_length\t%s\nmnc_length_raw\t%s\nbyte4\t%s\nrfu_bytes\t%s\n' \
        "$h" "$n" "$b1" "$mode_txt" "$mode" "$specific" "$b2" "$b3" \
        "$ciphering" "$csg" "$prose" "$edrx" "$mnc_len" "$mnc_bits" "${h:6:2}" "$extra"
    printf 'note_pin_flags\t%s\n' \
        "USIM EF_AD carries no PIN enable flags; PIN1/PIN2/ADM state is card state (ISO 7816-4 63Cx / 6983), and the ADM key is the vendor administrative key referenced by EF_ARR, not stored in EF_AD"
    return 0
}


# ── OTA: the SMS TPDU that carries a Toolkit Application (TS 23.048) ────
# An OTA SMS-DELIVER is an ordinary TS 23.040 TPDU whose TP-UD begins with
# the UDH information element IEI 0x70 ("OTA"), and the IE payload is a
# TS 23.048 secured Command Packet.
#
# Linear representation of the Command Packet (TS 23.048 §5.1, table 2):
#
#   CPI   1 octet   Command Packet Identifier (0x01 command, 0x02 response)
#   CPL   variable  Command Packet Length: octets from CHI to the end of
#                   the Secured Data, INCLUDING ciphering padding. CPL and
#                   CHL are BER-TLV lengths (TS 101 220 §5.1.1): one length
#                   octet, or 0x81/0x82 followed by 1/2 more.
#   CHI   1 octet   Command Header Identifier (0x01 command header)
#   CHL   variable  Command Header Length: octets from SPI to the end of
#                   the RC/CC/DS field.
#   SPI   2 octets  Security Parameter Indicator (see sim_spi_decode)
#   KIc   1 octet   Key/algorithm identifier for ciphering
#   KID   1 octet   Key/algorithm identifier for RC/CC/DS
#   TAR   3 octets  Toolkit Application Reference (application dependent)
#   CNTR  5 octets  Replay detection / sequence integrity counter
#   PCNTR 1 octet   Padding counter: padding octets at the end of the
#                   Secured Data
#   RC/CC/DS  variable, length = CHL - 14 (0 when the SPI says none)
#   Secured Data + padding
#
# Reading CPL as a single byte is the usual way a hand-rolled parser
# desynchronises on any packet over 255 octets, which is exactly the size of
# a real RFM file write.
sim_ota_berlen() {
    # BER-TLV length starting at byte offset $1 of hex string $2.
    # Echoes "<value> <bytes_consumed>".
    local off="$1" h="$2"
    local b0="${h:$(( off * 2 )):2}"
    [[ -n "$b0" ]] || return 1
    local v=$(( 16#$b0 ))
    if (( v < 0x80 )); then printf '%d 1\n' "$v"; return 0; fi
    if (( v == 0x80 )); then return 1; fi          # indefinite: forbidden
    local nb=$(( v & 0x7F ))
    (( nb >= 1 && nb <= 3 )) || return 1
    local val=0 k b
    for (( k = 1; k <= nb; k++ )); do
        b="${h:$(( (off + k) * 2 )):2}"
        [[ -n "$b" ]] || return 1
        val=$(( (val << 8) + 16#$b ))
    done
    printf '%d %d\n' "$val" "$(( nb + 1 ))"
}

sim_parse_ota() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 8 )) || { printf 'ERROR\tTPDU too short (%d bytes)\n' "$n" >&2; return 1; }

    local first; first=$(sim_hex_dec "${h:0:2}")
    local mti=$(( first & 0x03 ))
    local udhi=$(( (first >> 6) & 1 ))
    local mti_txt
    case "$mti" in
        0) mti_txt="SMS-DELIVER" ;;
        1) mti_txt="SMS-SUBMIT" ;;
        2) mti_txt="SMS-STATUS-REPORT" ;;
        3) mti_txt="Reserved" ;;
    esac
    local oa="" da="" pid="" dcs="" scts="" udl="" udstart=0
    if (( mti == 0 )); then
        # SMS-DELIVER: MTI|MMS|LP|SRI|UDHI|RP|0|0, then OA(2-12), PID, DCS, SCTS(7), UDL, UD
        # TS 23.040 §9.1.2.5: the address-length field counts SEMI-OCTETS
        # (digits), and the address field itself is ceil((len+1)/2) octets
        # because the TOA octet is additional to the counted digits.
        local oalen; oalen=$(sim_hex_dec "${h:2:2}")
        # oahex spans the TOA octet plus ceil(oalen/2) digit octets, so it
        # is (1 + ceil(oalen/2)) octets long. The digit loop skips index 0
        # (the TOA) and the parser resumes at pid_off.
        local oadigit_bytes=$(( (oalen + 1) / 2 ))
        local oabytes=$(( 1 + oadigit_bytes ))
        local oahex="${h:4:$(( oabytes * 2 ))}"
        local toa="${h:4:2}"
        local ton=$(( (16#$toa >> 4) & 0x07 ))
        local oadigits="" k
        for (( k = 1; k < oabytes; k++ )); do
            local bb="${oahex:$(( k * 2 )):2}"
            oadigits+="${bb:1:1}${bb:0:1}"
        done
        oadigits="${oadigits%[Ff]}"
        case "$ton" in
            1) oa="international +${oadigits}" ;;
            2) oa="national ${oadigits}" ;;
            5) oa="alphanumeric" ;;
            *) oa="unknown(ton=$ton) ${oadigits}" ;;
        esac
        local p=$(( 4 + oabytes * 2 ))
        pid="${h:$p:2}"; p=$(( p + 2 ))
        dcs="${h:$p:2}"; p=$(( p + 2 ))
        scts="${h:$p:14}"; p=$(( p + 14 ))
        udl=$(sim_hex_dec "${h:$p:2}"); p=$(( p + 2 ))
        udstart=$(( p / 2 ))
    else
        # SMS-SUBMIT: MTI|RD|VPF|SRR|UDHI|RP|MMS|0, then MR, DA, PID, DCS, [VP], UDL, UD
        # (TS 23.040 9.2.2.2). Two octets sit before the address and both were
        # being skipped wrongly: TP-MR immediately after the first octet, and
        # then the DA length. The old code read TP-MR as the address length, so
        # every SUBMIT decoded from that point on was garbage -- a push TPDU
        # reported its address-length octet as TP-PID and its TOA as TP-DCS.
        # TP-VPF in the first octet decides whether a VP octet follows the DCS:
        # 00 none, 01 one octet, 10 relative, 11 seven octets.
        local vpf=$(( (first >> 3) & 0x03 ))
        local daalen; daalen=$(sim_hex_dec "${h:4:2}")
        local daabytes=$(( (daalen + 1) / 2 ))
        local dahex="${h:6:$(( (1 + daabytes) * 2 ))}"
        local datoa="${h:6:2}"
        local daton=$(( (16#$datoa >> 4) & 0x07 ))
        local dadigits="" k
        for (( k = 1; k <= daabytes; k++ )); do
            local bb="${dahex:$(( k * 2 )):2}"
            dadigits+="${bb:1:1}${bb:0:1}"
        done
        dadigits="${dadigits%[Ff]}"
        case "$daton" in
            1) da="international +${dadigits}" ;;
            2) da="national ${dadigits}" ;;
            5) da="alphanumeric" ;;
            *) da="unknown(ton=$daton) ${dadigits}" ;;
        esac
        local p=$(( 2 + 2 + (1 + daabytes) * 2 ))
        pid="${h:$p:2}"; p=$(( p + 2 ))
        dcs="${h:$p:2}"; p=$(( p + 2 ))
        scts=""
        case "$vpf" in
            0) : ;;                       # TP-VP absent
            1|2) p=$(( p + 2 )) ;;        # one-octet VP
            3) p=$(( p + 14 )) ;;         # seven-octet absolute VP
        esac
        udl=$(sim_hex_dec "${h:$p:2}"); p=$(( p + 2 ))
        udstart=$(( p / 2 ))
    fi
    local dcs_val; dcs_val=$(sim_hex_dec "${dcs:-00}")
    local dcs_txt
    case $(( (dcs_val >> 4) & 0x03 )) in
        0) dcs_txt="GSM 7-bit default alphabet" ;;
        1) dcs_txt="8-bit data" ;;
        2) dcs_txt="UCS2" ;;
        *) dcs_txt="reserved" ;;
    esac
    (( dcs_val & 0x20 )) && dcs_txt="$dcs_txt (no class)"

    local ud="${h:$(( udstart * 2 ))}"
    local udbytes; udbytes=$(sim_hex_bytes "$ud")
    printf 'mti\t%s\nmti_code\t%s\nudhi\t%s\noa\t%s\nda\t%s\npid\t%s\ndcs\t%s\ndcs_meaning\t%s\nscts\t%s\nudl\t%s\nud_bytes\t%s\nud\t%s\nudh_present\t%s\n' \
        "$mti_txt" "$mti" "$udhi" "$oa" "$da" "$pid" "${dcs:-}" "$dcs_txt" "$scts" "$udl" "$udbytes" "$ud" \
        "$([[ $udhi -eq 1 ]] && echo yes || echo no)"

    if (( udhi != 1 )); then
        printf 'ota_valid\tno\nreason\tTP-UDHI is 0 — no UDH, therefore no 0x70 OTA information element\n'
        return 1
    fi
    (( udbytes >= 1 )) || { printf 'ERROR\tTP-UD empty\n' >&2; return 1; }
    local udhl; udhl=$(sim_hex_dec "${ud:0:2}")
    printf 'udhl\t%s\n' "$udhl"
    (( ${#ud} >= (udhl + 1) * 2 )) || {
        printf 'ERROR\tUDH claims %d bytes but TP-UD is only %d\n' "$udhl" "$udbytes" >&2
        return 1; }
    # Walk the IEs so a genuine text SMS with a concatenation IE (0x00) is
    # not mistaken for OTA: only IEI 0x70 is the TS 23.048 container.
    local iei70_off=""
    local j=2
    while (( j < (udhl + 1) * 2 )); do
        local iei="${ud:$j:2}"; j=$(( j + 2 ))
        (( j < ${#ud} + 1 )) || break
        local iedl; iedl=$(sim_hex_dec "${ud:$j:2}"); j=$(( j + 2 ))
        if [[ "${iei^^}" == "70" ]]; then iei70_off=$(( j )); break; fi
        j=$(( j + iedl * 2 ))
    done
    if [[ -z "$iei70_off" ]]; then
        printf 'ota_valid\tno\nreason\tno IEI 0x70 (OTA) information element in the UDH\n'
        return 1
    fi
    local pk="${ud:$iei70_off}"
    # Two packet layouts reach this point and they are not interchangeable.
    # The CAT_TP layout starts with a CPI octet (01/02) followed by a BER CPL,
    # a CHI and a BER CHL. The SMS layout of TS 31.115 4.2 has no CHI at all
    # and its CPL is a plain two-octet count, so its first octet is 00 for any
    # packet that fits in an SMS. That first octet is the discriminator.
    if [[ "${pk:0:2}" == "00" ]]; then
        sim_parse_ota_sms "$pk" "$udhl"
        return $?
    fi
    local pkbytes; pkbytes=$(sim_hex_bytes "$pk")
    (( pkbytes >= 15 )) || {
        printf 'ota_valid\tno\nreason\tCommand Packet is %d bytes; the minimum is 15 (CPI CPL CHI CHL SPI2 KIc KID TAR3 CNTR5 PCNTR)\n' "$pkbytes"
        return 1; }

    # CPI / CPL (BER-TLV length)
    local cpi="${pk:0:2}"
    local cpi_val; cpi_val=$(sim_hex_dec "$cpi")
    local cpi_txt
    case "$cpi_val" in
        1) cpi_txt="Command Packet (CPI=01)" ;;
        2) cpi_txt="Response Packet (CPI=02)" ;;
        *) cpi_txt="unknown CPI (reserved)" ;;
    esac
    local cpl_out; cpl_out=$(sim_ota_berlen 1 "$pk") || {
        printf 'ERROR\tCPL at offset 1 is not a valid BER-TLV length\n' >&2; return 1; }
    local cpl="${cpl_out% *}" cpl_len="${cpl_out#* }"
    # CHI / CHL
    local chi_off=$(( 1 + cpl_len ))
    local chi="${pk:$(( chi_off * 2 )):2}"
    local chi_val; chi_val=$(sim_hex_dec "$chi")
    local chi_txt
    case "$chi_val" in
        1) chi_txt="Command Header (CHI=01)" ;;
        2) chi_txt="Response Header (CHI=02)" ;;
        *) chi_txt="unknown CHI (reserved)" ;;
    esac
    local chl_out; chl_out=$(sim_ota_berlen $(( chi_off + 1 )) "$pk") || {
        printf 'ERROR\tCHL is not a valid BER-TLV length\n' >&2; return 1; }
    local chl="${chl_out% *}" chl_len="${chl_out#* }"
    local spi_off=$(( chi_off + 1 + chl_len ))
    (( pkbytes >= spi_off + 14 )) || {
        printf 'ERROR\tCommand Header needs %d bytes from offset %d but the packet is %d\n' \
            14 "$spi_off" "$pkbytes" >&2; return 1; }

    local spi_hex="${pk:$(( spi_off * 2 )):4}"
    local spi=$(( 16#$spi_hex ))
    local kic="${pk:$(( (spi_off + 2) * 2 )):2}"
    local kid="${pk:$(( (spi_off + 3) * 2 )):2}"
    local tar="${pk:$(( (spi_off + 4) * 2 )):6}"
    local cntr="${pk:$(( (spi_off + 7) * 2 )):10}"
    local pcntr="${pk:$(( (spi_off + 12) * 2 )):2}"
    # CHL counts from the SPI to the end of the RC/CC/DS field (TS 102 225 5.1
    # Table 1), and the eight octets before that field are SPI(2) KIc(1) KID(1)
    # TAR(3) CNTR(5) PCNTR(1) -- thirteen, not fourteen. Reading fourteen
    # starts the CC one octet early, which shifts the whole secured payload.
    local rccds_len=$(( chl - 13 ))
    (( rccds_len < 0 )) && rccds_len=0
    local rccds="${pk:$(( (spi_off + 13) * 2 )):$(( rccds_len * 2 ))}"
    local secured_off=$(( spi_off + 13 + rccds_len ))
    local secured="${pk:$(( secured_off * 2 ))}"
    # CPL should account for everything from CHI to the end of the secured
    # data. A mismatch means the packet is truncated or the length coding
    # is non-standard, which is worth saying out loud rather than ignoring.
    # CPL counts octets from CHI to the end of the Secured Data, so the
    # packet must be exactly chi_off + cpl octets long. A mismatch means
    # the packet is truncated or uses non-standard length coding, and the
    # secured-data slice below would be silently wrong.
    local expected_cpl=$(( chi_off + cpl ))
    local cpl_note="consistent"
    if (( expected_cpl != pkbytes )); then
        cpl_note="CPL says the packet is $expected_cpl bytes (CHI at $chi_off + CPL $cpl) but the IE carries $pkbytes — truncated or non-standard length coding"
    fi

    printf 'ota_valid\tyes\ndialect\tts102.225-cat-tp\nudhl\t%s\ncpi\t%s\ncpi_meaning\t%s\ncpl\t%s\ncpl_len_octets\t%s\nchi\t%s\nchi_meaning\t%s\nchl\t%s\nchl_len_octets\t%s\nspi_off\t%s\ncpl_check\t%s\n' \
        "$udhl" "$cpi" "$cpi_txt" "$cpl" "$cpl_len" "$chi" "$chi_txt" "$chl" "$chl_len" "$spi_off" "$cpl_note"
    printf 'spi\t%s\nspi_hex\t%s\n' "$spi" "$spi_hex"
    sim_spi_decode "$spi"

    # KIc/KID: the octet is a key reference, and bits b8b7 carry the
    # algorithm family while the low bits select the key set.
    sim_kic_kid_meaning "$kic" cipher
    sim_kic_kid_meaning "$kid" integrity
    printf 'tar\t%s\ntar_known\t%s\n' "$tar" "$(sim_ota_tar_name "$tar")"
    # The raw octets, so the key audit downstream reads the packet rather than
    # falling back to 00 for a key that is right there.
    printf 'kic\t%s\nkid\t%s\n' "$kic" "$kid"
    printf 'cntr_hex\t%s\ncntr\t%s\npcntr\t%s\n' "$cntr" "$(sim_hex_dec "$cntr")" "$pcntr"
    printf 'rccds_len\t%s\nrccds\t%s\nsecured_data_len\t%s\nsecured_data\t%s\n' \
        "$rccds_len" "$rccds" "$(sim_hex_bytes "$secured")" "$secured"
    # A CC is eight octets and a response checksum four (TS 102 225 5.1.1), so
    # any other length means this packet is not one the clause describes.
    case "$rccds_len" in
        0) : ;;
        8|4) : ;;
        *) printf 'rccds_note\tCHL is %s, so the RC/CC/DS field is %s octets; a CC is 8 and a response checksum 4, so this packet does not follow TS 102 225 5.1.1\n' \
               "$chl" "$rccds_len" ;;
    esac

    # Replay exposure, stated against the SPI rather than assumed.
    local cbits=$(( (spi >> 11) & 0x03 ))
    case "$cbits" in
        0) printf 'replay_note\tSPI b5b4=00 — the RE ignores CNTR, so this packet can be replayed verbatim\n' ;;
        1) printf 'replay_note\tSPI b5b4=01 — CNTR is informational only; no replay protection is enforced\n' ;;
        2) printf 'replay_note\tSPI b5b4=10 — the RE accepts if CNTR > its stored value (tolerant, allows gaps)\n' ;;
        3) printf 'replay_note\tSPI b5b4=11 — the RE accepts only CNTR == stored+1 (strict sequence integrity)\n' ;;
    esac
    if [[ "$cntr" == "0000000000" ]]; then
        printf 'cntr_note\tCNTR is zero — ether a freshly provisioned card or a packet captured before the first legitimate send\n'
    fi
    return 0
}

# KIc/KID octet (TS 23.048 §5.1.2 / §5.1.3):
#   b8b7  algorithm: 00 implicit | 01 DES | 10 reserved | 11 proprietary
#   b6b5  mode for KIc: 00 DES-CBC | 01 3DES outer-CBC 2 keys |
#                       10 3DES outer-CBC 3 keys | 11 DES-ECB
#         mode for KID: 00 DES-CBC | 01 3DES 2 keys | 10 3DES 3 keys |
#                       11 reserved
#   b4..b1  key set reference (implementation defined)
# The mode is where the real strength sits: 3DES with two keys is 112-bit
# effective, and DES-ECB has no chaining at all.
sim_kic_kid_meaning() {
    local v="${1^^}" kind="${2:-cipher}"
    [[ "$v" =~ ^[0-9A-F]{2}$ ]] || { printf 'ERROR\tkey identifier must be one hex byte\n' >&2; return 2; }
    local val=$(( 16#$v ))
    # TS 102 225 §5.1.2: b8..b5 key set, b4b3 mode, b2b1 algorithm family.
    # Reading the nibbles the other way round (family from b8b7, "key set"
    # from the low nibble) inverts every strength conclusion below.
    local family=$(( val & 0x03 ))
    local mode=$(( (val >> 2) & 0x03 ))
    local keyset=$(( (val >> 4) & 0x0F ))
    local alg_txt
    case "$family" in
        0) alg_txt="algorithm known implicitly by both entities" ;;
        1) alg_txt="DES (ISO 8731-1 DEA)" ;;
        2) alg_txt="reserved" ;;
        3) alg_txt="proprietary implementation" ;;
    esac
    local mode_txt
    if [[ "$kind" == "cipher" ]]; then
        case "$mode" in
            0) mode_txt="DES in CBC mode (56-bit key, zero IV)" ;;
            1) mode_txt="Triple DES outer-CBC with two keys (112-bit effective)" ;;
            2) mode_txt="Triple DES outer-CBC with three keys (168-bit)" ;;
            3) mode_txt="DES in ECB mode (no chaining — identical plaintext blocks produce identical ciphertext)" ;;
        esac
    else
        case "$mode" in
            0) mode_txt="DES in CBC mode (56-bit key)" ;;
            1) mode_txt="Triple DES outer-CBC with two keys (112-bit effective)" ;;
            2) mode_txt="Triple DES outer-CBC with three keys (168-bit)" ;;
            3) mode_txt="reserved" ;;
        esac
    fi
    local strength="strong"
    case "$family" in
        0) strength="weak — implicit algorithm, no negotiated strength" ;;
        1) case "$mode" in
               0) strength="weak — single DES, 56-bit key" ;;
               1) strength="weak — 2-key 3DES, 112-bit effective" ;;
               2) strength="acceptable — 3-key 3DES" ;;
               3) strength="critical — DES-ECB, 56-bit key and no chaining" ;;
           esac ;;
        2) strength="unknown — reserved algorithm identifier" ;;
        3) strength="unknown — proprietary, cannot be assessed" ;;
    esac
    printf '%s_hex\t0x%s\n%s_algorithm\t%s\n%s_family\t%s\n' \
        "$kind" "$v" "$kind" "$alg_txt" "$kind" "$family"
    printf '%s_mode_meaning\t%s\n' "$kind" "$mode_txt"
    printf '%s_mode\t%s\n%s_mode_bits\t%s\n%s_key_set\t%s\n%s_strength\t%s\n' \
        "$kind" "$mode" "$kind" "$mode" "$kind" "$keyset" "$kind" "$strength"
    return 0
}

# The KIc/KID pair from a Command Header, decoded together. The decoded field
# that matters for a key-recovery attack is the key set, which is the high
# nibble -- not the low one, which is the algorithm and its mode.
sim_cmd_ota_key() {
    local kic="${1:-}" kid="${2:-}" ks kds
    [[ -n "$kic" ]] || { printf 'ERROR\tusage: --ota-key <KIc> [<KID>]\n' >&2; return 2; }
    sim_kic_kid_meaning "$kic" cipher || return $?
    ks=$(sim_kic_kid_meaning "$kic" cipher | awk -F'\t' '$1=="cipher_key_set"{print $2}')
    if [[ -n "$kid" ]]; then
        sim_kic_kid_meaning "$kid" integrity || return $?
        kds=$(sim_kic_kid_meaning "$kid" integrity | awk -F'\t' '$1=="integrity_key_set"{print $2}')
        if [[ -n "$ks" && "$ks" == "$kds" ]]; then
            printf 'finding\tMEDIUM\tKIc and KID name the same key set %s — one recovered key breaks confidentiality and integrity together\n' "$ks"
        fi
    fi
    if [[ "$ks" == "1" ]]; then
        printf 'finding\tMEDIUM\tkey set 1 is the first-provisioned set, the one most often deployed with a fixed diversification input\n'
    fi
    return 0
}


# The SPI bit fields (ETSI TS 102 225 §5.1.1, with the SMS-only bit from
# TS 31.115 §4.2). The field order in that clause is not the bit order, and
# reading the printed table top to bottom is what produces an SPI that says
# "ciphering on" about a payload in the clear. Two statements of the same
# clause fix the bits: it names the command's integrity field "SPI1.b2b1",
# and it says "SPI2.b4b3 shall be set to the same value as SPI1.b2b1" when
# the PoR carries the same protection.
#
#   First octet:
#     b8..b6  Reserved, set to zero and ignored by the RE
#     b5 b4   Counter:   00 no counter available | 01 counter, no replay
#                        checking | 10 process iff counter > RE value |
#                        11 process iff counter is exactly RE+1
#     b3      Ciphering: 0 no ciphering | 1 ciphering
#     b2 b1   RC/CC/DS:  00 none | 01 Redundancy Check | 10 Cryptographic
#                        Checksum | 11 Digital Signature
#   Second octet:
#     b8 b7   Reserved, set to zero
#     b6      SMS only (TS 31.115 §4.2): 0 PoR via SMS-DELIVER-REPORT,
#                        1 PoR via SMS-SUBMIT
#     b5      PoR response ciphering: 0 not ciphered | 1 ciphered
#     b4 b3   RC/CC/DS applied to the PoR response: 00 none | 01 simple RC
#                         | 10 CC | 11 DS
#     b2 b1   PoR reply mode: 00 none | 01 required | 10 on error only |
#                         11 reserved
sim_spi_decode() {
    local spi="${1:-}"
    [[ "$spi" =~ ^[0-9]+$ ]] || { printf 'ERROR\tSPI must be decimal\n' >&2; return 2; }
    (( spi >= 0 && spi <= 65535 )) || { printf 'ERROR\tSPI out of 16-bit range\n' >&2; return 2; }

    local o1=$(( (spi >> 8) & 0xFF )) o2=$(( spi & 0xFF ))
    printf 'spi\t%s\nspi_hex\t%04X\nspi_octet1\t%02X\nspi_octet2\t%02X\n' "$spi" "$spi" "$o1" "$o2"

    # ── first octet ──
    local rccds=$(( o1 & 0x03 ))
    local ciphering=$(( (o1 >> 2) & 0x01 ))
    local counter=$(( (o1 >> 3) & 0x03 ))
    local reserved1=$(( (o1 >> 5) & 0x07 ))
    local rccds_txt
    case "$rccds" in
        0) rccds_txt="no RC, CC or DS" ;;
        1) rccds_txt="Redundancy Check (RC)" ;;
        2) rccds_txt="Cryptographic Checksum (CC)" ;;
        3) rccds_txt="Digital Signature (DS)" ;;
    esac
    local counter_txt
    case "$counter" in
        0) counter_txt="no counter available (field present but ignored by the RE)" ;;
        1) counter_txt="counter available, NO replay or sequence checking" ;;
        2) counter_txt="process iff counter value is higher than the value in the RE" ;;
        3) counter_txt="process iff counter value is exactly RE+1 (strict)" ;;
    esac
    printf 'spi_b2b1_rccds\t%s\nspi_rccds\t%s\n' "$rccds" "$rccds_txt"
    printf 'spi_b3_ciphering\t%s\n' "$ciphering"
    printf 'spi_ciphering\t%s\n' "$([[ $ciphering -eq 1 ]] && echo "applied" || echo "NOT applied (payload in the clear)")"
    printf 'spi_b5b4_counter\t%s\nspi_counter\t%s\n' "$counter" "$counter_txt"
    printf 'spi_b8b7b6_reserved\t%s\n' "$reserved1"

    # ── second octet ──
    local por=$(( o2 & 0x03 ))
    local por_rccds=$(( (o2 >> 2) & 0x03 ))
    local por_cipher=$(( (o2 >> 4) & 0x01 ))
    local por_sms=$(( (o2 >> 5) & 0x01 ))
    local reserved2=$(( (o2 >> 6) & 0x03 ))
    local por_txt
    case "$por" in
        0) por_txt="no PoR reply to the Sending Entity" ;;
        1) por_txt="PoR required to be sent to the SE" ;;
        2) por_txt="PoR required only when an error has occurred" ;;
        3) por_txt="reserved" ;;
    esac
    local por_rccds_txt
    case "$por_rccds" in
        0) por_rccds_txt="no RC, CC or DS applied to the PoR" ;;
        1) por_rccds_txt="PoR response with simple RC" ;;
        2) por_rccds_txt="PoR response with CC" ;;
        3) por_rccds_txt="PoR response with DS" ;;
    esac
    printf 'spi_b2b1_por\t%s\nspi_por\t%s\n' "$por" "$por_txt"
    printf 'spi_b4b3_por_rccds\t%s\nspi_por_rccds\t%s\n' "$por_rccds" "$por_rccds_txt"
    printf 'spi_b5_por_ciphering\t%s\n' "$por_cipher"
    printf 'spi_b6_por_submit\t%s\n' "$por_sms"
    printf 'spi_por_transport\t%s\n' "$([[ $por_sms -eq 1 ]] && echo "SMS-SUBMIT" || echo "SMS-DELIVER-REPORT")"
    printf 'spi_b8b7_por_reserved\t%s\n' "$reserved2"

    # ── findings ──
    # Every branch states the mechanism that is missing, because the whole
    # point of decoding an SPI is to know what actually protects the packet.
    local findings=""
    (( ciphering == 0 )) && findings+="${findings:+; }SPI b3=0 — the command payload is NOT ciphered"
    case "$counter" in
        0) findings+="${findings:+; }SPI b5b4=00 — no anti-replay counter is applied" ;;
        1) findings+="${findings:+; }SPI b5b4=01 — the counter is informational only, so a captured packet can be replayed" ;;
    esac
    (( rccds == 0 )) && findings+="${findings:+; }SPI b2b1=00 — no RC/CC/DS, so the packet has no integrity protection at all"
    if [[ -z "$findings" ]]; then
        printf 'spi_weakness\tnone — ciphering on (b3=1), counter enforced (b5b4=%s), integrity %s\n' \
            "$(printf '%02d' "$counter")" "$rccds_txt"
    else
        printf 'spi_weakness\t%s\n' "$findings"
    fi
    return 0
}


# Toolkit Application References that are publicly documented. A TAR in
# this table is a card-side application a forged OTA packet can drive.
sim_ota_tar_name() {
    case "${1^^}" in
        B00001) echo "SIM Toolkit (ETSI TS 101 267 operator TAR allocation)" ;;
        B00002) echo "SIM Data Download (TS 23.048 §5.1)" ;;
        B00003) echo "SIM Toolkit Menu / S@T browser TAR range" ;;
        B00004) echo "SIM File System provisioning (RFM) — TS 23.048" ;;
        B00005) echo "Remote File Management (RFM) — TS 23.048" ;;
        B00010) echo "S@T browser (SIMalliance S@T v1.x)" ;;
        B00020) echo "Java Card applet installer TAR" ;;
        B00030) echo "OTA RAM / bearer independent protocol" ;;
        BB0000|BB0001|BB0002|BB0003) echo "Operator-provisioned RFM TAR" ;;
        535400|535401) echo "'ST' — seen on Gemalto/Thales cards for RFM" ;;
        *)      echo "unknown TAR" ;;
    esac
}

# OTA key derivation weak points, as published in the SIM/OTA literature.
# These are properties of the deployed key provisioning practice, not of
# the 03.48 format itself, so they are reported as findings with a reason.
sim_ota_key_weakness() {
    local kic="${1^^}" kid="${2^^}"
    # Callers may hand over an already-prefixed value ("0x01") or an empty
    # one. Normalise to exactly two hex digits or refuse, because 16# on an
    # empty operand aborts the enclosing command substitution.
    kic="${kic#0X}"; kid="${kid#0X}"
    kic="${kic// /}"; kid="${kid// /}"
    [[ "$kic" =~ ^[0-9A-F]{1,2}$ ]] || kic="00"
    [[ "$kid" =~ ^[0-9A-F]{1,2}$ ]] || kid="00"
    kic=$(printf '%02X' "$(( 16#$kic ))")
    kid=$(printf '%02X' "$(( 16#$kid ))")
    local kic_val kid_val
    kic_val=$(( 16#$kic )); kid_val=$(( 16#$kid ))
    local out=""
    # The bits come from sim_kic_kid_meaning, not from a second reading of
    # them: the key set number is the high nibble (b8..b5), the mode is b4b3
    # and the algorithm family is b2b1, per TS 102 225 §5.1.2.
    local kic_dec kid_dec
    kic_dec=$(sim_kic_kid_meaning "$kic" cipher) || return $?
    kid_dec=$(sim_kic_kid_meaning "$kid" integrity) || return $?
    local kic_mode kic_alg kid_mode kid_alg
    kic_mode=$(printf '%s\n' "$kic_dec" | awk -F'\t' '$1=="cipher_mode"{print $2}')
    kic_alg=$(printf '%s\n' "$kic_dec" | awk -F'\t' '$1=="cipher_family"{print $2}')
    kid_mode=$(printf '%s\n' "$kid_dec" | awk -F'\t' '$1=="integrity_mode"{print $2}')
    kid_alg=$(printf '%s\n' "$kid_dec" | awk -F'\t' '$1=="integrity_family"{print $2}')

    if (( kic_val == 0 || kid_val == 0 )); then
        out="O1: mechanism not applied (KIc=0x${kic} KID=0x${kid}) — the packet is not both ciphered and integrity protected"
    fi
    if (( kic_alg == 1 && kic_mode == 0 )); then
        out="${out:+$out; }O2: KIc selects single DES-CBC — 56-bit key, brute-forceable for a known-plaintext OTA packet"
    fi
    if (( kic_alg == 1 && kic_mode == 3 )); then
        out="${out:+$out; }O2b: KIc selects DES-ECB — no chaining, so identical plaintext blocks yield identical ciphertext and the payload leaks structure"
    fi
    if (( kic_alg == 1 && kic_mode == 1 )); then
        out="${out:+$out; }O3: KIc selects 2-key 3DES outer-CBC — 112-bit effective strength"
    fi
    if (( kic_alg == 0 || kid_alg == 0 )); then
        out="${out:+$out; }O4: algorithm identifier is 00 (implicitly known) — the strength is not negotiated on the wire and cannot be verified from the packet alone"
    fi
    if (( kic_alg == 3 || kid_alg == 3 )); then
        out="${out:+$out; }O5: proprietary algorithm identifier — not assessable from the packet"
    fi
    if (( kid_alg == 1 && kid_mode == 0 )); then
        out="${out:+$out; }O6: KID selects single DES-CBC for integrity — 56-bit, and a forged CC defeats the command"
    fi
    if (( kid_alg == 1 && kid_mode == 1 )); then
        out="${out:+$out; }O7: KID selects 2-key 3DES — 112-bit effective integrity protection"
    fi
    # The deployment weakness this module exists to flag: one key set used
    # for both directions means one recovery breaks confidentiality and
    # integrity together.
    local kic_set kid_set
    kic_set=$(printf '%s\n' "$kic_dec" | awk -F'\t' '$1=="cipher_key_set"{print $2}')
    kid_set=$(printf '%s\n' "$kid_dec" | awk -F'\t' '$1=="integrity_key_set"{print $2}')
    if (( kic_val != 0 && kic_val == kid_val )); then
        out="${out:+$out; }O8: KIc == KID (key set ${kic_set}) — a single recovered key breaks both confidentiality and integrity"
    elif (( kic_val != 0 && kic_set == kid_set )); then
        out="${out:+$out; }O9: KIc and KID reference key set ${kic_set} — the same provisioned material is reused across both functions"
    fi
    if (( kic_set == 1 && kic_val != 0 )); then
        out="${out:+$out; }O10: key set 1 is the factory/first-provisioned set, the one most often deployed with a fixed diversification input"
    fi
    if [[ -n "$out" ]]; then
        printf 'ota_key_weakness\t%s\n' "$out"
    else
        printf 'ota_key_weakness\tnone of the known derivation weaknesses matched KIc=0x%s KID=0x%s\n' "$kic" "$kid"
    fi
    return 0
}

# ── eSIM / RSP (SGP.22) ─────────────────────────────────────────────────
# The profile metadata is an ASN.1 SEQUENCE of context-tagged fields; the
# store is TLV-encoded so a hand-rolled walk is honest about what it found.
sim_parse_profile_metadata() {
    local h; h=$(sim_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$h")
    (( n >= 2 )) || { printf 'ERROR\tmetadata too short\n' >&2; return 1; }
    printf 'raw\t%s\nbytes\t%s\n' "$h" "$n"

    # SGP.22 profile metadata is a nested DER SEQUENCE, so a flat sibling
    # walk stops at the first constructed field and reports a profile with
    # no ICCID in it. This walk descends into constructed values (tag bit
    # 0x20 set) and into the context-tagged [n] wrappers SGP.22 uses for
    # every field, printing a depth column so the tree is visible.
    #
    # Scope is an explicit stack of (start, end) byte offsets. When the
    # cursor reaches the end of the innermost scope it is popped, which is
    # the only correct way to leave a nested SEQUENCE.
    local any=0
    local -a sc_start=(0) sc_end=("$(( ${#h} / 2 ))")
    local i=0 depth=0

    while (( i < ${#sc_end[@]} ? 0 : 0 )); do :; done   # no-op keeps set -u calm
    while (( ${#sc_start[@]} > 0 )); do
        local top=$(( ${#sc_start[@]} - 1 ))
        local limit=${sc_end[$top]}
        if (( i >= limit )); then
            unset 'sc_start[top]' 'sc_end[top]'
            sc_start=("${sc_start[@]}"); sc_end=("${sc_end[@]}")
            (( depth > 0 )) && depth=$(( depth - 1 ))
            continue
        fi
        [[ $(( (i + 1) * 2 )) -le ${#h} ]] || break
        local tag="${h:$(( i * 2 )):2}"
        local tval=$(( 16#$tag ))
        local tagstr="$tag"
        i=$(( i + 1 ))
        # High-tag-number form (ISO 8825-1): low 5 bits all ones pulls a
        # second tag octet. SGP.22 does not use it yet, but a walker that
        # silently misreads it desynchronises on any future profile.
        if (( (tval & 0x1F) == 0x1F )); then
            [[ $(( (i + 1) * 2 )) -le ${#h} ]] || break
            tagstr="$tag${h:$(( i * 2 )):2}"; i=$(( i + 1 ))
        fi
        [[ $(( (i + 1) * 2 )) -le ${#h} ]] || {
            printf 'error\ttruncated length octet at offset %d\n' "$i"; return 1; }
        local lb="${h:$(( i * 2 )):2}"
        local lval=$(( 16#$lb )); i=$(( i + 1 ))
        if (( lval == 0x80 )); then
            printf 'error\tindefinite length in a SGP.22 metadata blob (DER forbids it)\n'
            return 1
        elif (( lval == 0x81 )); then
            [[ $(( (i + 1) * 2 )) -le ${#h} ]] || { printf 'error\ttruncated 0x81 length\n'; return 1; }
            lval=$(( 16#${h:$(( i * 2 )):2} )); i=$(( i + 1 ))
        elif (( lval == 0x82 )); then
            [[ $(( (i + 2) * 2 )) -le ${#h} ]] || { printf 'error\ttruncated 0x82 length\n'; return 1; }
            lval=$(( 16#${h:$(( i * 2 )):2} )); i=$(( i + 1 ))
            lval=$(( (lval << 8) + 16#${h:$(( i * 2 )):2} )); i=$(( i + 1 ))
        elif (( lval > 0x82 )); then
            printf 'error\tlength form 0x%s not supported\n' "$lb"
            return 1
        fi
        # A value running past its enclosing scope is a truncated blob.
        if (( i + lval > limit )); then
            printf 'error\ttag 0x%s at offset %d claims %d bytes but only %d remain in scope\n' \
                "${tag^^}" "$(( i - 1 ))" "$lval" "$(( limit - i ))"
            return 1
        fi
        local name
        case "${tag^^}" in
            30) name="SEQUENCE (ProfileMetadata / StoreMetadata)" ;;
            A0) name="[0] profileVersion" ;;
            A1) name="[1] iccid / IntegratedCircuitCardIdentifier" ;;
            A2) name="[2] serviceProviderName" ;;
            A3) name="[3] profileName" ;;
            A4) name="[4] iconType" ;;
            A5) name="[5] icon" ;;
            A6) name="[6] profileClass" ;;
            A7) name="[7] notificationConfigurationInfo" ;;
            A8) name="[8] profileOwner" ;;
            A9) name="[9] profilePolicyRules" ;;
            AA) name="[10] serviceProviderInfo" ;;
            AB) name="[11] profileNickname" ;;
            AC) name="[12] profileState / PPK" ;;
            04) name="OCTET STRING" ;;
            0C) name="UTF8String" ;;
            13) name="PrintableString" ;;
            16) name="IA5String" ;;
            02) name="INTEGER" ;;
            03) name="BIT STRING" ;;
            01) name="BOOLEAN" ;;
            05) name="NULL" ;;
            *)  if (( tval & 0x20 )); then name="tag 0x${tag^^} (constructed, unmapped)"
                else name="tag 0x${tag^^} (unmapped in this walker)"; fi ;;
        esac
        printf 'field\t%s\t%s\t%s\t%s\n' "$depth" "$tagstr" "$lval" "$name"
        any=1
        if (( tval & 0x20 )) && (( lval > 0 )); then
            # Descend: the value is a new scope. The cursor stays at the
            # first octet of the value and the child scope ends after it.
            sc_start+=("$i"); sc_end+=("$(( i + lval ))")
            depth=$(( depth + 1 ))
        else
            i=$(( i + lval ))          # primitive: skip the value
        fi
    done
    printf 'fields_ok\tyes\n'
    return 0
}

# The RSP roles (GSMA SGP.22 v2.x): SM-DP+ (Subscription Manager Data
# Preparation Plus) prepares and protects a profile, the LPA (Local Profile
# Assistant) on the device drives the download, SM-DS is the discovery
# service, and the eUICC (eSIM chip, EUM-certified) is the target.
sim_rsp_roles() {
    cat <<'EOF'
sm-dp+	Subscription Manager Data Preparation Plus — authenticates the eUICC, prepares and protects the profile, serves it over HTTPS (initiateAuthentication / authenticateClient / getBoundProfilePackage)
sm-ds	Subscription Manager Discovery Service — publishes and resolves pending profile orders so the LPA learns which SM-DP+ to contact
lpa	Local Profile Assistant — on the device (in the modem or on the eUICC); owns the ES10x interface to the eUICC and drives the download
euicc	eUICC — the secure element; holds the ISD-R, the profiles and the key material; GSMA-certified (EUM) at the security-assurance level
isd-r	Issuer Security Domain Root — the eUICC's RSP entry point, drives ES10b (profile download, enable, disable, delete)
isd-p	Issuer Security Domain Profile — one per installed profile, holds the profile's keys and the MNO's OTA keys
EOF
}

# Profile lifecycle per SGP.22 §2.5.5 / ES10b. A profile is in exactly one
# state, and the mapping to the mobile equipment is strict: only an enabled
# profile can be attached to, and enabling one disables the other.
# ── profile state machine: the sequences the spec forbids (R12) ─────────
#
# An eUICC holds profiles in exactly three states -- enabled, disabled, deleted
# (SGP.22 2.6.1) -- and the interesting attacks are not in the states but in the
# sequences: a delete while enabled, two profiles enabled at once, an enable of
# something already deleted. Each of those is a sentence the spec writes and a
# card is supposed to enforce; this models the sentences so a sequence can be
# judged before it is run at a card that cannot answer questions.
#
# The event file is one operation per line:
#   install <iccid>    ES10b.LoadBoundProfilePackage: arrives disabled
#   enable <iccid>     ES10b.EnableProfile: disables whichever profile held the slot
#   disable <iccid>    ES10b.DisableProfile
#   delete <iccid>     ES10b.DeleteProfile: only from disabled
#   list               ES10b.ListProfile: records what the eUICC reports
# '#' starts a comment.
sim_profile_model() {
    local file="${1:-}"
    [[ -n "$file" ]] || {
        printf 'ERROR\tusage: --profile-model <events-file>\n' >&2
        printf 'NOTE\t  one operation per line: install|enable|disable|delete <iccid>, or list\n' >&2
        return 2; }
    if [[ "$file" != "-" && ! -r "$file" ]]; then
        printf 'ERROR\tno readable event file at %s\n' "$(sim_sanitize "$file")" >&2
        return 1
    fi
    printf 'model\tprofile state machine\n'
    printf 'spec\tSGP.22 2.6.1 (Profile State), 5.7.x (ES10b profile management)\n'
    printf 'states\tenabled, disabled, deleted\n'
    local src="$file"
    [[ "$src" == "-" ]] && src=/dev/stdin
    local -A state=() has=()
    local n=0 line op iccid findings=0 enabled_slot=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        op="${line%% *}"; iccid=""
        [[ "$line" == *" "* ]] && iccid="$(printf '%s' "${line#* }" | tr -d ' ')"
        op="${op,,}"
        n=$(( n + 1 ))
        case "$op" in
            list)
                printf 'event.%d\tlist\t-\t-\t%s\n' "$n" \
                    "$(for k in "${!state[@]}"; do printf '%s=%s ' "$k" "${state[$k]}"; done)"
                continue ;;
            install|enable|disable|delete) ;;
            *)
                printf 'ERROR\tevent %d: unknown operation %s (install|enable|disable|delete|list)\n' \
                    "$n" "$(sim_sanitize "$op")" >&2
                return 1 ;;
        esac
        [[ "$iccid" =~ ^[0-9A-Fa-f]{16,20}$ ]] || {
            printf 'ERROR\tevent %d: %s needs an ICCID (8..10 octets of hex)\n' "$n" "$op" >&2
            return 1; }
        iccid="${iccid^^}"
        local before="${state[$iccid]:-absent}"
        local after="$before" verdict="ok" rule=""
        case "$op" in
            install)
                if [[ "$before" != "absent" ]]; then
                    verdict="refused"; rule="an ICCID is installed once; a second LoadBoundProfilePackage for it is a duplicate (5.7.5)"
                elif [[ -n "$enabled_slot" ]]; then
                    after="disabled"
                    rule="a new profile arrives disabled; the enabled profile keeps the slot (2.6.1, 5.7.6)"
                else
                    after="disabled"
                    rule="a new profile arrives disabled (2.6.1)"
                fi ;;
            enable)
                if [[ "$before" == "absent" ]]; then
                    verdict="refused"; rule="nothing to enable: the ICCID was never installed"
                elif [[ "$before" == "deleted" ]]; then
                    verdict="refused"; rule="a deleted profile cannot be enabled; it is removed, not hidden (2.6.1)"
                elif [[ "$before" == "enabled" ]]; then
                    verdict="refused"; rule="the profile is already enabled"
                else
                    if [[ -n "$enabled_slot" && "$enabled_slot" != "$iccid" ]]; then
                        state["$enabled_slot"]="disabled"
                        printf 'event.%d.side\t%s\tdisabled\t%s\n' "$n" "$enabled_slot" \
                            "enabling one profile disables the one that held the slot (5.7.6)"
                    fi
                    after="enabled"; enabled_slot="$iccid"
                    rule="exactly one profile is enabled at a time (2.6.1)"
                fi ;;
            disable)
                if [[ "$before" == "absent" ]]; then
                    verdict="refused"; rule="nothing to disable: the ICCID was never installed"
                elif [[ "$before" == "deleted" ]]; then
                    verdict="refused"; rule="a deleted profile has no state to change"
                elif [[ "$before" == "disabled" ]]; then
                    verdict="refused"; rule="the profile is already disabled"
                else
                    after="disabled"; enabled_slot=""
                    rule="the slot is now empty; the modem has no profile to attach with"
                fi ;;
            delete)
                if [[ "$before" == "absent" ]]; then
                    verdict="refused"; rule="nothing to delete: the ICCID was never installed"
                elif [[ "$before" == "enabled" ]]; then
                    verdict="refused"
                    rule="a profile must be disabled before it is deleted (5.7.7); deleting the enabled one is the sequence the spec forbids"
                elif [[ "$before" == "deleted" ]]; then
                    verdict="refused"; rule="the profile is already deleted"
                else
                    after="deleted"
                    rule="ISD-P removed; re-installing the same ICCID is a fresh download (2.6.1)"
                fi ;;
        esac
        if [[ "$verdict" == "refused" ]]; then
            findings=$(( findings + 1 ))
        else
            state["$iccid"]="$after"
        fi
        printf 'event.%d\t%s\t%s\t%s\t%s\n' "$n" "$op" "$iccid" "$before" "$after"
        [[ -n "$rule" ]] && printf 'event.%d.rule\t%s\n' "$n" "$rule"
        printf 'event.%d.verdict\t%s\n' "$n" "$verdict"
    done < "$src"
    printf 'events\t%d\n' "$n"
    printf 'refused\t%d\n' "$findings"
    local k count=0
    for k in "${!state[@]}"; do
        printf 'final.%s\t%s\n' "$k" "${state[$k]}"
        count=$(( count + 1 ))
    done
    printf 'profiles\t%d\n' "$count"
    local enabled_count=0
    for k in "${!state[@]}"; do [[ "${state[$k]}" == "enabled" ]] && enabled_count=$(( enabled_count + 1 )); done
    if (( enabled_count > 1 )); then
        printf 'finding\tHIGH\t%d profiles enabled at once; an eUICC has one enabled slot (2.6.1)\n' "$enabled_count"
        findings=$(( findings + 1 ))
    fi
    if (( findings > 0 )); then
        printf 'verdict\t%s\n' "the sequence contains $findings step(s) the spec forbids; a card that accepted them is not enforcing 2.6.1 and 5.7.x"
        printf 'sent\t0\n'
        return 1
    fi
    printf 'verdict\t%s\n' "every step is a transition SGP.22 allows; the sequence is legal by this model, which is not the same as a card having run it"
    printf 'sent\t0\n'
    return 0
}

sim_profile_state_table() {
    cat <<'EOF'
state	es10_command	me_visible	notes
enabled	ES10b.EnableProfile	yes	the one profile the modem attaches with; enabling it disables the previously enabled profile
disabled	ES10b.DisableProfile	no	installed and intact but not selectable by the modem; keys retained
deleted	ES10b.DeleteProfile	no	ISD-P removed; the profile cannot be recovered without re-downloading from the SM-DP+
EOF
}

# ── hardware guards ─────────────────────────────────────────────────────
# An empty result is not an answer: each guard names what is missing.
sim_find_reader() {
    if [[ -n "${SIM_READER:-}" ]]; then printf '%s\n' "$SIM_READER"; return 0; fi
    if command -v pcsc_scan >/dev/null 2>&1; then
        local r
        r=$(timeout 3 pcsc_scan -r 2>/dev/null | sed -n 's/.*Reader [0-9]*: *//p' | head -n1)
        if [[ -n "$r" ]]; then printf '%s\n' "$r"; return 0; fi
    fi
    if command -v opensc-tool >/dev/null 2>&1; then
        local r
        r=$(timeout 3 opensc-tool --list-readers 2>/dev/null | sed -n 's/^#.*: *//p' | head -n1)
        if [[ -n "$r" ]]; then printf '%s\n' "$r"; return 0; fi
    fi
    return 1
}

sim_find_sim_tool() {
    local t
    for t in pySim-shell.py pySim-read.py osmocom-sim-tool simtrace2-cardem; do
        command -v "$t" >/dev/null 2>&1 && { printf '%s\n' "$t"; return 0; }
    done
    return 1
}

# ── plan files ──────────────────────────────────────────────────────────
# Every workflow that needs hardware writes a plan file whose first line
# after the header is `status: handoff`, and names the exact hardware.
sim_plan_hardware() {
    case "${1:-}" in
        ota-replay) echo "an SMSC you control (Osmocom SMSC or a test SMSC link) plus a programmable USIM (sysmoUSIM-SJS1) whose OTA key set is known" ;;
        sat-wib)    echo "a programmable USIM (sysmoUSIM-SJS1 or Sysmocom SJA2/SJS1) with OTA keys you hold, plus a phone or an Osmocom testbed to receive the proactive commands" ;;
        esim-download) echo "an eUICC with test-profile capability (a 5.2+ eUICC in a PC/SC reader, or a removable eSIM such as a 5ber/eSTK test card) plus a GSMA SM-DP+ test account (test profile server)" ;;
        apdu-live)  echo "a PC/SC reader (any CCID reader; ACR38U or SCM SCR3310 both work) plus pcscd, and a UICC you are authorised to read" ;;
        dpa-lab)    echo "a UICC you own, a PC/SC reader (ACR38U or SCM SCR3310) to drive it, and a current probe or an EM probe plus an oscilloscope with a trigger the reader's clock can drive (a PicoScope 5244D or equivalent) — the card must be yours, since a DPA capture is a physical teardown of the key" ;;
        *)          echo "unknown plan" ;;
    esac
}

sim_plan() {
    local kind="${1:-}"
    case "$kind" in
        ota-replay|sat-wib|esim-download|apdu-live|dpa-lab) ;;
        *) printf 'ERROR\tunknown plan: %s (want ota-replay|sat-wib|esim-download|apdu-live|dpa-lab)\n' "${kind:-<none>}" >&2; return 2 ;;
    esac
    local hw; hw=$(sim_plan_hardware "$kind")
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$SIM_PLAN_DIR"
    local f="$SIM_PLAN_DIR/plan_${kind}_${ts}.txt"
    {
        echo "plan: $kind"
        echo "status: handoff"
        echo "hardware: $hw"
        echo "ts: $(date -Is)"
        echo
        sim_plan_body "$kind"
    } | tee "$f"
    printf 'plan_file\t%s\nstatus\thandoff\n' "$f"
    return 0
}

sim_plan_body() {
    case "$1" in
    ota-replay)
        cat <<'EOF'
objective
  Determine whether a target UICC accepts an OTA (TS 23.048) command packet
  whose CNTR is at or below the card's anti-replay high-water mark, and
  whether the operator applied ciphering and integrity (SPI bits 14 and 13).
  A replayed packet that still executes is the "OTA replay" finding.

why this needs hardware
  The security of an OTA packet is enforced entirely inside the card by the
  OTA engine (KIc/KID key set) and by the anti-replay counter state. Neither
  is observable from the air or from a capture: the CNTR is a 5-byte
  monotonic value held in non-volatile memory on the UICC, and the key set
  is only addressed by index in the SPI header. There is no software stand-in.

prerequisites
  * PC/SC reader + pcscd running, card inserted and powered
  * a programmable USIM whose OTA keys you control (sysmoUSIM-SJS1)
  * an SMSC path to deliver the SMS: an Osmocom SMSC, or a GSM testbed
  * the captured OTA TPDU you intend to replay, from a pcap or GSMTAP feed
  * python3 + the osmocom 'pySim' shell for raw APDU work

procedure
  1. Read the provisioning state from the card:
       modules/16_sim.sh --build-apdu A0 A4 00 00 7F20   # DF_GSM
       modules/16_sim.sh --build-apdu A0 A4 00 00 6F73   # EF_AD
       modules/16_sim.sh --parse-apdu <response hex>
     Record EF_AD byte 3 (ADM flag) and byte 4 (OPC/ADC/MBI/SPN flags).
  2. Capture a legitimate OTA SMS for the target app (TAR), for example:
       tcpdump -i any -w ota.pcap 'udp port 4729 or port 4242'
       modules/17_pcap_analysis.sh --extract ota.pcap <frame> gsmtap
       modules/16_sim.sh --parse-ota <tpdu hex>
     Note the TAR, the SPI and the five CNTR bytes.
  3. Re-send the same TPDU a second time, unchanged.
  4. If the card acts on the second delivery, anti-replay is not enforced
     for that TAR/key set. If it rejects, the CNTR high-water mark is live.
  5. Re-send with CNTR decremented by one and with CNTR left unchanged but
     the SPI ciphering bit cleared, for the two downgrade variants.
  6. Record the outcome against the key set. A rejection on one TAR does not
     generalise: the OTA engine keeps a counter per key set, not per card.

evidence to keep
  * the TPDU hex, the SPI decode and the TAR for each attempt
  * the response APDU (SW1 SW2) for each attempt
  * whether the card executed the command (observable as a proactive
    command, an EF write, or an SMS-STATUS-REPORT per the SPI receipt bits)

safety
  Do not run this against a UICC you do not own or have written authorisation
  for. A replay that writes to EF_IMSI or EF_KEYS can render the card
  unusable for its real subscription.
EOF
        ;;
    sat-wib)
        cat <<'EOF'
objective
  Drive a SIM Toolkit proactive command from the card by sending an OTA
  SMS that the S@T browser (or a WIB/WIB-capable STK applet) will execute:
  a Send Short Message, a Setup Call, a Provide Local Information or a
  Send SS command. This is the S@T/WIB path documented in the SIM
  attack literature.

why this needs hardware
  The proactive command is executed by the card's STK runtime and handed to
  the terminal over the 102.221 T=0/T=1 interface. Both ends are physical:
  the card must be a programmable UICC loaded with the target applet (or an
  operator card whose TAR you have), and the terminal must be a phone or a
  modem that will honour the proactive command.

prerequisites
  * programmable USIM (sysmoUSIM-SJS1) with an STK/S@T applet and known OTA keys
  * a terminal: an Android phone with the card in it, or an Osmocom
    testbed (osmo-bts + osmo-msc) with a modem (Quectel/Simcom) as the UE
  * SMSC path to deliver the OTA SMS
  * the S@T bytecode for the command you intend (Send SMS, Setup Call)

procedure
  1. Enumerate the installed toolkit apps and their TARs:
       modules/16_sim.sh --selftest            # confirms the TAR table loads
       pySim-shell.py -p 0  ->  select MF; select DF_GSM
     Read EF_SST/EF_UST to see which STK services are enabled (bitmap per
     TS 31.102 §4.2.47), and note whether "S@T browser" is among them.
  2. Build the 03.48 packet for the TAR:
       modules/16_sim.sh --parse-ota <captured or crafted TPDU hex>
     The SPI must request ciphering and a receipt so the outcome is
     observable; CNTR must be strictly increasing.
  3. Wrap it in an SMS-DELIVER with TP-UDHI=1 and IEI 0x70 and deliver it
     through the SMSC to the card in the phone.
  4. Observe the terminal: a Setup Call command raises a call to the number
     in the S@T bytecode; a Send SMS command emits an SMS and returns an
     SMS-STATUS-REPORT; Provide Local Information returns IMEI/location.
  5. Record which commands were accepted, plus the SPI/TAR/CNTR that
     produced each one.

evidence to keep
  * the delivered TPDU hex and its --parse-ota decode per command
  * the proactive command observed at the terminal (TERMINAL RESPONSE)
  * the SMS-STATUS-REPORT / SMS-DELIVER generated by the card

why it matters
  A terminal that executes card-originated Setup Call / Send SMS without a
  user prompt lets whoever can emit OTA traffic act as the subscriber.
  WIB (the Wireless Internet Browser family) had the same shape: browser
  state driven by card data with a command surface reachable from an SMS.

safety
  Only against a card and terminal you own. A S@T applet that places a call
  will place a real, billed call.
EOF
        ;;
    esim-download)
        cat <<'EOF'
objective
  Perform a full SGP.22 profile download against an eUICC: authenticate to
  an SM-DP+, fetch and install a profile, then observe the profile state
  transitions (disabled -> enabled) and what the modem sees.

why this needs hardware
  The RSP flow is anchored in the eUICC's EUM-certified key material and in
  the SM-DP+ server. There is no way to complete (or meaningfully test) the
  authentication chain without a real eUICC and a real SM-DP+ test account.

prerequisites
  * eUICC with test capability, in a PC/SC reader (removable eSIM or a
    5.2+ eUICC dev sample)
  * pcscd running; lpac (the open-source LPA) or the vendor LPA tool
  * a GSMA SM-DP+ test account / test profile server and its activation code
    (AC format: 1$<SM-DP+ FQDN>$<matchingId>$<OID>$<confirmation code req>)

procedure
  1. Read the eUICC identity and the ISD-R:
       lpac info            # EUICCInfo1/2, EID, SVN, RSP capabilities
     The EID is the eUICC's serial; EUICCInfo reports the RSP version and
     the supported CI public key ids.
  2. Walk the ES10x surface the download will use:
       modules/16_sim.sh --parse-apdu <STORE DATA response hex>
     The download runs as a sequence of ES10b.StoreData blocks over the
     ISD-R with the BPP (Bound Profile Package) segmented by the LPA.
  3. Trigger the download with the activation code:
       lpac profile download -a '<activation code>'
     This is ES9+ initiateAuthentication -> authenticateClient ->
     getBoundProfilePackage against the SM-DP+.
  4. List and inspect the result:
       lpac profile list     # each entry: ICCID, ISD-P AID, state, nickname
     Profile metadata per SGP.22 carries: profileVersion, iccid,
     serviceProviderName, profileName, profileClass, profileOwner,
     profilePolicyRules, and the profile state.
  5. Enable the new profile and confirm the disable of the previous one:
       lpac profile enable <iccid>
     Only one profile is enabled at a time; enabling is destructive to the
     previous enabled state.
  6. Delete the profile and confirm it is unrecoverable:
       lpac profile delete <iccid>
     Deletion removes the ISD-P; re-installation requires a new download.

evidence to keep
  * `lpac info` output (EID, EUICCInfo, supported RSP versions)
  * the profile list before/after each state transition
  * the ASN.1 metadata for each downloaded profile:
      modules/16_sim.sh --parse-apdu ...   (or the raw metadata hex)

attack surface worth recording while you are here
  * an unsigned or wrongly-signed profile package is rejected by the eUICC
    only if the CI public key set is correct — record which CI keys the
    eUICC holds
  * profilePolicyRules can carry ppk (profile policy: deletion/disable
    control); a rule that permits deletion is a resilience weakness
  * the LPA is the trust boundary on the device: an LPA that trusts the
    SM-DP+ hostname from the activation code without pinning the CI key
    chain is the usual finding

safety
  Use a test SM-DP+ and a test eUICC. A production profile downloaded to a
  test chip, or a delete on a production eUICC, is destructive.
EOF
        ;;
    apdu-live)
        cat <<'EOF'
objective
  Run the ISO-7816 command set of this module against a real card: SELECT
  the MF/DF/EF hierarchy, READ BINARY and READ RECORD the identity files,
  and record the response APDUs with their status words.

why this needs hardware
  Commands require a UICC physically connected over T=0/T=1 through a
  reader. The encoders in this module are complete; only the transport is
  missing here.

prerequisites
  * PC/SC reader (ACR38U, SCM SCR3310, or any CCID reader) + pcscd
  * a UICC you are authorised to read
  * pySim-shell.py (osmocom) for a scriptable APDU transport

procedure
  1. Confirm the reader is visible:
       modules/16_sim.sh --status-tsv
  2. SELECT the master file, then the USIM ADF, then each EF:
       modules/16_sim.sh --build-apdu A0 A4 00 00 3F00      # MF
       modules/16_sim.sh --build-apdu A0 A4 00 00 7FFF      # ADF_USIM
       modules/16_sim.sh --build-apdu A0 A4 00 00 2FE2      # EF_ICCID
  3. READ BINARY the ICCID (10 bytes at offset 0) and decode:
       modules/16_sim.sh --build-apdu A0 B0 00 00 0A
       modules/16_sim.sh --decode-iccid <data hex>
  4. Read EF_IMSI (transparent, 9 bytes including the length byte):
       modules/16_sim.sh --build-apdu A0 B0 00 00 09
       modules/16_sim.sh --decode-imsi <data hex>
  5. Read EF_AD and interpret the administrative data:
       modules/16_sim.sh --build-apdu A0 B0 00 00 04
       modules/16_sim.sh --parse-apdu <response hex>    # then --decode-ad
  6. A 61 xx response means more data is waiting: issue GET RESPONSE with
     the length from SW2.
       modules/16_sim.sh --build-apdu A0 C0 00 00 0A

notes on authorisation
  EF_ADM and the ADM keys are not readable. The ADM key is the card
  vendor's administrative key; without it, EF_IMSI/EF_KEYS cannot be
  rewritten, and that is exactly the control that stops a cloned card from
  being re-provisioned by a third party.
EOF
        ;;
    dpa-lab)
        cat <<'EOF'
DPA capture against COMP128-1 — what this module models and what it does not.

what is already computed here
  modules/16_sim.sh --dpa-model <ki> <rand>
      the level-0 leakage point x[a] = T0[(ki[j] + 2*rand[j]) & 511] for each
      of the 16 key bytes, with the address, the table output and its Hamming
      weight. RAND is attacker-chosen, so each key byte is attacked at its own
      position independently.
  modules/16_sim.sh --dpa-sim <ki> [traces] [sigma]
      synthesises traces from that model, correlates each of the 256 key-byte
      candidates per position, and then PROVES the recovered key by running
      COMP128-1 on challenges the trace set never contained.
  tools/gsm_crypto.py --dpa-sweep --ki <ki>
      recovery against noise (sigma 0..5), against trace count (16..512) and
      against a deliberately wrong leakage model, which is expected to fail.

what this is not
  The traces are synthetic. There is no oscilloscope, no probe and no card in
  this path, and none of the numbers above are a measurement. They bound what
  the attack needs — the model has to be right, the traces have to be clean —
  and nothing more.

the capture, step by step
  1. Owned UICC in a PC/SC reader. The ATR confirms the card class; a card that
     answers A3/A8 locally with COMP128-1 is the target of this attack.
  2. Trigger. The reader's clock (CLK) is the natural trigger; the COMP128-1
     computation follows the RUN GSM ALGORITHM APDU (A0 88 00 00 10 || RAND ||
     Le=0x10) by a fixed latency, so trigger on the last CLA/INS byte and delay
     into the window rather than triggering on the current spike itself.
  3. Probe. A current probe on the card's Vcc/GND path, or an EM probe over the
     die for a contactless or de-capped card. Sample at 5-10x the card clock.
  4. Alignment. Every trace must be aligned to the same clock edge. Jitter
     eats the correlation faster than noise does — if the attack fails, check
     alignment before adding traces.
  5. Inputs. Record the RAND sent with each trace. The attack needs the RAND,
     not just the power trace, and a trace whose RAND was not logged is
     useless.
  6. Analysis. Feed the traces and RANDs to --dpa-sim's model; the correlation
     is per key-byte position, and the recovered key is then verified by
     running COMP128-1 forward.

what the model tells you to expect
  With this leakage model, 16 traces already separate the right key byte from
  all 256 candidates, and recovery survives noise well past the point where a
  real capture would be considered clean. Real captures are dominated by
  alignment and by whether the leakage is the Hamming weight of T0's output at
  all — a masked card makes that assumption false, and a masked card is
  precisely what COMP128-2/-3 and later generations are.
EOF
        ;;
    esac
    return 0
}

# ── APDU log ────────────────────────────────────────────────────────────
# One TSV row per APDU this module builds or parses, so a later module can
# replay the exact sequence against a card.
sim_log_init() {
    mkdir -p "$SIM_DIR"
    if [[ ! -f "$SIM_APDU_LOG" ]]; then
        printf 'ts\tdirection\thex\tcase\tsw\tstatus\tnote\n' > "$SIM_APDU_LOG"
    fi
}

sim_log_apdu() {
    local dir="${1:-?}" hex="${2:-}" case="${3:-}" sw="${4:-}" status="${5:-}" note="${6:-}"
    sim_log_init
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -Is)" "$(sim_sanitize "$dir")" "$(sim_sanitize "$hex")" \
        "$(sim_sanitize "$case")" "$(sim_sanitize "$sw")" \
        "$(sim_sanitize "$status")" "$(sim_sanitize "$note")" >> "$SIM_APDU_LOG"
}

sim_log_count() {
    [[ -f "$SIM_APDU_LOG" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$SIM_APDU_LOG" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
sim_cli_status_tsv() {
    local reader tool n
    reader=$(sim_find_reader) || reader="none"
    tool=$(sim_find_sim_tool) || tool="none"
    n=$(sim_log_count)
    printf 'reader\t%s\n'        "$(sim_sanitize "$reader")"
    printf 'sim_tool\t%s\n'      "$(sim_sanitize "$tool")"
    printf 'pcscd\t%s\n'         "$(command -v pcscd >/dev/null 2>&1 && echo present || echo missing)"
    printf 'apdu_log\t%s\n'      "$SIM_APDU_LOG"
    printf 'apdu_count\t%s\n'    "$n"
    printf 'plans\t%s\n'         "$SIM_PLAN_DIR"
    printf 'plan_count\t%s\n'    "$(find "$SIM_PLAN_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
    printf 'dir\t%s\n'           "$SIM_DIR"
    printf 'files_known\t%s\n'   20
}

sim_cmd_build_apdu() {
    local cla="${1:-}" ins="${2:-}" p1="${3:-}" p2="${4:-}" data="${5:-}" le="${6:-}"
    [[ -n "$cla" && -n "$ins" && -n "$p1" && -n "$p2" ]] || {
        printf 'ERROR\tusage: --build-apdu <cla> <ins> <p1> <p2> [data-hex] [le-hex]\n' >&2
        return 2
    }
    local out rc
    out=$(sim_build_apdu "$cla" "$ins" "$p1" "$p2" "$data" "$le"); rc=$?
    (( rc == 0 )) || return "$rc"
    printf '%s\n' "$out"
    local hex case
    hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="apdu_hex"{print $2}')
    case=$(printf '%s\n' "$out" | awk -F'\t' '$1=="case"{print $2}')
    sim_log_apdu "C-APDU" "$hex" "$case" "-" "-" "built by --build-apdu"
    return 0
}

sim_cmd_parse_apdu() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --parse-apdu <hex>\n' >&2; return 2; }
    local n; n=$(sim_hex_bytes "$(sim_norm_hex "$h")")
    if (( n == 2 )); then
        # A bare SW with no data is the common case for a plain status query.
        local out; out=$(sim_parse_rapdu "$h") || return 1
        printf '%s\n' "$out"
        sim_log_apdu "R-APDU" "$(sim_norm_hex "$h")" "-" "$(sim_norm_hex "$h")" \
            "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "status word only"
        (sim_sw_ok "$h") && return 0 || return 3
    fi
    local seq; seq=$(sim_parse_capdu "$h"); local rc=$?
    if (( rc == 0 )); then
        printf 'kind\tcommand\n%s\n' "$seq"
        sim_log_apdu "C-APDU" "$(sim_norm_hex "$h")" "$(printf '%s\n' "$seq" | awk -F'\t' '$1=="case"{print $2}')" \
            "-" "-" "parsed by --parse-apdu"
        return 0
    fi
    seq=$(sim_parse_rapdu "$h") || {
        printf 'ERROR\t%s is neither a valid command APDU nor a response APDU\n' "$h" >&2
        return 1
    }
    local sw; sw=$(printf '%s\n' "$seq" | awk -F'\t' '$1=="sw"{print $2}')
    printf 'kind\tresponse\n%s\n' "$seq"
    sim_log_apdu "R-APDU" "$(sim_norm_hex "$h")" "-" "$sw" \
        "$(printf '%s\n' "$seq" | awk -F'\t' '$1=="status"{print $2}')" "parsed by --parse-apdu"
    (sim_sw_ok "$sw") && return 0 || return 3
}

sim_cmd_decode_iccid() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --decode-iccid <hex>\n' >&2; return 2; }
    sim_decode_iccid "$h"
}

sim_cmd_decode_imsi() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --decode-imsi <hex>\n' >&2; return 2; }
    sim_decode_imsi "$h"
}

sim_cmd_decode_ad() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --decode-ad <hex>\n' >&2; return 2; }
    sim_parse_ef_ad "$h"
}

# TS 31.115 4.2: the single-SMS Command Packet. CPL is two octets and CHL is
# one, neither BER-coded; there is no Command Header Identifier. The security
# header is SPI(2) KIc(1) KID(1) TAR(3), then CNTR(5) PCNTR(1) [CC(8)] and the
# secured data -- all of which the SPI may declare ciphered.
sim_parse_ota_sms() {
    local pk="${1:-}" udhl="${2:-}"
    local n; n=$(sim_hex_bytes "$pk")
    (( n >= 10 )) || { printf 'ERROR\tSMS command packet too short (%d bytes)\n' "$n" >&2; return 1; }
    local cpl=$(( 16#${pk:0:4} ))
    local chl=$(( 16#${pk:4:2} ))
    local spi_hex="${pk:6:4}"
    local kic="${pk:10:2}" kid="${pk:12:2}" tar="${pk:14:6}"
    (( cpl == n - 2 )) || {
        printf 'ERROR\tCPL says %d octets after the CPL field, the packet carries %d\n' \
            "$cpl" "$(( n - 2 ))" >&2
        return 1
    }
    printf 'ota_valid\tyes\ndialect\tts31.115-sms-packet\nudhl\t%s\ncpi\t-\ncpi_meaning\tnone in this layout (TS 31.115 4.2 has no Command Header Identifier)\n' "$udhl"
    printf 'cpl\t%d\ncpl_len_octets\t2\nchl\t%d\nchl_len_octets\t1\n' "$cpl" "$chl"
    local spi=$(( 16#${spi_hex} )) counter cipher
    printf 'spi_off\t2\nspi\t%s\nspi_hex\t%s\n' "$spi" "$spi_hex"
    sim_spi_decode "$spi"
    counter=$(sim_spi_decode "$spi" | awk -F'\t' '$1=="spi_counter"{print $2}')
    cipher=$(sim_spi_decode "$spi" | awk -F'\t' '$1=="spi_ciphering"{print $2}')
    local sig=0
    (( chl == 21 )) && sig=8
    if (( chl != 13 && chl != 21 )); then
        printf 'chl_note\tCHL is %d; the header is 13 octets without a CC and 21 with one (TS 102 225 5.1.1)\n' "$chl"
    fi
    printf 'header_bytes\t%d\ncc_bytes\t%d\n' "$chl" "$sig"
    sim_kic_kid_meaning "$kic" cipher
    sim_kic_kid_meaning "$kid" integrity
    printf 'tar\t%s\ntar_known\t%s\n' "$tar" "$(sim_ota_tar_name "$tar")"
    printf 'kic\t%s\nkid\t%s\n' "$kic" "$kid"
    if [[ "$cipher" == "applied" ]]; then
        # The key is the card's, and guessing at plaintext would be inventing
        # the one thing an attacker actually needs to know.
        printf 'secured\tyes (SPI b3=1)\nsecured_note\tthe header after TAR, the counter and the payload are enciphered; this verb does not decrypt. Run modules/41_ota_sms.sh --parse-packet-sms with OTASM_KIC_KEY/OTASM_KID_KEY to read them (it also verifies the CC)\n'
    else
        local cntr="${pk:20:10}" pcntr="${pk:30:2}"
        printf 'secured\tno (SPI b3=0)\ncounter\t%s\npcntr\t%s\n' "$cntr" "$pcntr"
        (( sig == 8 )) && printf 'cc\t%s\n' "${pk:32:16}"
        printf 'apdu\t%s\n' "${pk:$(( 32 + sig * 2 ))}"
    fi
    return 0
}

sim_cmd_parse_ota() {
    local h="${1:-}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --parse-ota <tpdu-hex>\n' >&2; return 2; }
    local out; out=$(sim_parse_ota "$h"); local rc=$?
    printf '%s\n' "$out"
    if (( rc != 0 )); then
        printf 'ERROR\tTPDU is not a TS 23.048 OTA command packet\n' >&2
        return 1
    fi
    local kic kid spi tar
    kic=$(printf '%s\n' "$out" | awk -F'\t' '$1=="kic"{print $2; exit}')
    kid=$(printf '%s\n' "$out" | awk -F'\t' '$1=="kid"{print $2; exit}')
    spi=$(printf '%s\n' "$out" | awk -F'\t' '$1=="spi"{print $2; exit}')
    tar=$(printf '%s\n' "$out" | awk -F'\t' '$1=="tar"{print $2; exit}')
    # The parser reports KIc/KID through sim_kic_kid_meaning, so the raw
    # octets are read back from the packet representation rather than
    # guessed. Fall back to 00 (mechanism not applied) when absent.
    kic="${kic:-0x00}"; kid="${kid:-0x00}"
    sim_ota_key_weakness "${kic#0x}" "${kid#0x}"
    printf 'attack_surface\tspi=%s tar=%s kic=%s kid=%s\n' "$spi" "$tar" "$kic" "$kid"
    sim_log_apdu "OTA-SMS" "$(sim_norm_hex "$h")" "-" "-" "parsed" "TAR $tar SPI $spi"
    return 0
}

sim_cmd_select() {
    local fid="${1:-}"
    [[ -n "$fid" ]] || { printf 'ERROR\tusage: --select-fid <fid>\n' >&2; return 2; }
    local out; out=$(sim_apdu_select_fid "$fid") || return $?
    printf '%s\n' "$out"
    printf 'file\t%s\n' "$(sim_file_name "$fid")"
    printf 'path\t%s\n' "$(sim_file_path "$fid")"
    local hex; hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="apdu_hex"{print $2}')
    sim_log_apdu "C-APDU" "$hex" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="case"{print $2}')" "-" "-" "SELECT $fid"
}

sim_cmd_read_binary() {
    local off="${1:-0}" le="${2:-0}"
    local out; out=$(sim_apdu_read_binary "$off" "$le") || return $?
    printf '%s\n' "$out"
    local hex; hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="apdu_hex"{print $2}')
    sim_log_apdu "C-APDU" "$hex" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="case"{print $2}')" "-" "-" "READ BINARY off=$off le=$le"
}

sim_cmd_read_record() {
    local rec="${1:-1}" mode="${2:-04}" le="${3:-0}"
    local out; out=$(sim_apdu_read_record "$rec" "$mode" "$le") || return $?
    printf '%s\n' "$out"
    local hex; hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="apdu_hex"{print $2}')
    sim_log_apdu "C-APDU" "$hex" "$(printf '%s\n' "$out" | awk -F'\t' '$1=="case"{print $2}')" "-" "-" "READ RECORD $rec"
}

sim_cmd_get_response() {
    local le="${1:-0}"
    local out; out=$(sim_apdu_get_response "$le") || return $?
    printf '%s\n' "$out"
}

sim_cmd_plan() {
    local kind="${1:-}"
    [[ -n "$kind" ]] || { printf 'ERROR\tusage: --plan <ota-replay|sat-wib|esim-download|apdu-live|dpa-lab>\n' >&2; return 2; }
    sim_plan "$kind"
}

# ── DPA side-channel model (COMP128-1) ──────────────────────────────────
# The model itself lives in tools/gsm_crypto.py, next to the COMP128-1 tables
# it depends on. Copying the S-boxes and the T0 table into shell is exactly the
# drift this tree has been bitten by before, so 16_sim owns the SIM-domain
# verbs and delegates the arithmetic.
#
# WHAT IS REAL: the leakage point, the correlation, the key recovery, the
# noise/trace-count behaviour, and the fact that a wrong leakage model fails.
# All of it is computed.
#
# WHAT IS NOT: no oscilloscope, no probe, no card. Traces are synthesised from
# the leakage model with a seeded RNG, and every verb says so on stdout.
sim_dpa_tool() {
    local tool="$IMSISTING_ROOT/tools/gsm_crypto.py"
    [[ -f "$tool" ]] || { printf 'ERROR\ttools/gsm_crypto.py is missing\n' >&2; return 3; }
    printf '%s\n' "$tool"
}

# --dpa-model <ki> <rand> : the level-0 leakage point for each key byte.
sim_dpa_model() {
    local ki="${1:-}" rand="${2:-}" tool
    [[ "$ki" =~ ^[0-9A-Fa-f]{32}$ && "$rand" =~ ^[0-9A-Fa-f]{32}$ ]] || return 2
    tool=$(sim_dpa_tool) || return $?
    printf 'scope\tmodel of the leakage point; trace acquisition is a handoff (--plan dpa-lab)\n'
    python3 "$tool" --dpa-leak --ki "$ki" --rand "$rand" || return 1
}

# --dpa-sim <ki> [traces] [sigma] : synthesise traces, recover the key, verify
# the recovered key against COMP128-1 on held-out challenges.
sim_dpa_sim() {
    local ki="${1:-}" traces="${2:-256}" sigma="${3:-1.0}" tool
    [[ "$ki" =~ ^[0-9A-Fa-f]{32}$ ]] || return 2
    [[ "$traces" =~ ^[0-9]+$ ]] || return 2
    [[ "$sigma" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 2
    tool=$(sim_dpa_tool) || return $?
    python3 "$tool" --dpa-sim --ki "$ki" --traces "$traces" --sigma "$sigma" || return 1
}

# --dpa-sweep <ki> : noise / trace-count / leakage-model sweeps.
sim_dpa_sweep() {
    local ki="${1:-}" tool
    [[ "$ki" =~ ^[0-9A-Fa-f]{32}$ ]] || return 2
    tool=$(sim_dpa_tool) || return $?
    python3 "$tool" --dpa-sweep --ki "$ki" || return 1
}

# ── SIM authentication algorithms (COMP128 / Milenage / TUAK) ──────────
# The algorithms live in tools/gsm_crypto.py, next to the tables they depend
# on. Re-implementing AES, Keccak or the COMP128 S-boxes in shell is the drift
# this tree has been bitten by before, so 16_sim owns the verbs, the 3GPP field
# naming (RES/CK/IK/AUTN rather than f1..f5*) and the published-vector
# assertions, and delegates the arithmetic.
#
# WHAT IS REAL: SRES/Kc for the three COMP128 variants, f1..f5* for Milenage
# and TUAK, and the AUTN that follows from f1/f5. Every value is computed.
#
# WHAT IS NOT: the tool emits no AUTN and no AUTS. AUTN is assembled here from
# f1/f5 and says so; AUTS is not built, because it needs a second run over
# SQN_MS. Nothing touches a card: the 3GPP secret K/OP/TOP has to come from
# somewhere you already have it.

sim_kv() { # sim_kv <key> <captured tsv block> -> value of the first matching row
    # Pure bash: this runs a few hundred times in one selftest, and a fork per
    # lookup is most of the cost.
    local k="$1" row_k row_v
    [[ -n "${2:-}" ]] || return 1
    while IFS=$'\t' read -r row_k row_v; do
        if [[ "$row_k" == "$k" ]]; then printf '%s' "$row_v"; return 0; fi
    done <<<"$2"
    return 1
}

sim_auth_xor() { # XOR of two equal-length hex strings, uppercase hex out
    local a="${1^^}" b="${2^^}" i out=""
    (( ${#a} == ${#b} && ${#a} % 2 == 0 )) || return 1
    for ((i = 0; i < ${#a}; i += 2)); do
        out+=$(printf '%02X' $(( (16#${a:i:2} ^ 16#${b:i:2}) & 0xFF )))
    done
    printf '%s' "$out"
}

sim_auth_usage() {
    printf 'ERROR\tusage: --sim-auth <comp128-1|comp128-2|comp128-3|milenage|tuak> <ki-hex> <rand-hex> [--op <hex>|--opc <hex>|--top <hex>] [--sqn <hex>] [--amf <hex>] [--klength 128|256] [--iterations 1|2]\n' >&2
}

# The tool's f1..f5* rows, re-labelled with the field names a USIM/AuC uses,
# plus the AUTN the network puts on the wire.
sim_auth_umts_rows() {
    local raw="$1" sqn="$2" amf="$3" pair v ak maca autn
    # TUAK output lengths are per-vector (TS 35.232 names MAC_sz, RES_sz, CK_sz
    # and IK_sz per row), so the sizes the tool actually used are passed through
    # rather than left implicit: two runs with different RES_sz give different
    # f2..f5 and the rows below are only reproducible with the sizes in view.
    for pair in mac_sz res_sz ck_sz ik_sz; do
        v=$(sim_kv "$pair" "$raw")
        [[ -n "$v" ]] && printf '%s\t%s\n' "$pair" "$v"
    done
    for pair in f1 'f1*' f2 f3 f4 f5 'f5*'; do
        v=$(sim_kv "$pair" "$raw")
        [[ -n "$v" ]] && printf '%s\t%s\n' "$pair" "$v"
    done
    for pair in res:f2 ck:f3 ik:f4 ak:f5 mac_a:f1 mac_s:'f1*'; do
        v=$(sim_kv "${pair#*:}" "$raw")
        [[ -n "$v" ]] && printf '%s\t%s\n' "${pair%%:*}" "$v"
    done
    ak=$(sim_kv f5 "$raw")
    maca=$(sim_kv f1 "$raw")
    if [[ -n "$sqn" && -n "$amf" && -n "$ak" && -n "$maca" ]]; then
        autn="$(sim_auth_xor "$sqn" "$ak")${amf}${maca}"
        printf 'autn\t%s\n' "$autn"
        printf 'autn_basis\tSQN xor f5 || AMF || f1 (3GPP TS 33.102 AUTN); assembled by this module, the tool emits no AUTN\n'
    else
        printf 'note\tf1, f1* and therefore AUTN need both --sqn (12 hex) and --amf (4 hex)\n'
    fi
}

# --sim-auth <algo> <ki> <rand> [--op|--opc|--top] [--sqn] [--amf] [--klength] [--iterations]
sim_cmd_sim_auth() {
    local algo="${1:-}"
    shift 2>/dev/null || true
    case "$algo" in
        comp128-1|comp128-2|comp128-3|milenage|tuak) ;;
        '') sim_auth_usage; return 2 ;;
        *)  printf 'ERROR\tunknown algorithm %s; expected comp128-1, comp128-2, comp128-3, milenage or tuak\n' \
                "$(sim_sanitize "$algo")" >&2
            return 2 ;;
    esac
    local ki="${1:-}" rand="${2:-}"
    shift 2 2>/dev/null || true
    [[ -n "$ki" && -n "$rand" ]] || { sim_auth_usage; return 2; }

    local op='' opc='' top='' sqn='' amf='' klength=128 iterations=1
    while (( $# )); do
        case "$1" in
            --op)         op="${2:-}";         shift 2 2>/dev/null || shift ;;
            --opc)        opc="${2:-}";        shift 2 2>/dev/null || shift ;;
            --top)        top="${2:-}";        shift 2 2>/dev/null || shift ;;
            --sqn)        sqn="${2:-}";        shift 2 2>/dev/null || shift ;;
            --amf)        amf="${2:-}";        shift 2 2>/dev/null || shift ;;
            --klength)    klength="${2:-}";    shift 2 2>/dev/null || shift ;;
            --iterations) iterations="${2:-}"; shift 2 2>/dev/null || shift ;;
            *) printf 'ERROR\tunsupported flag %s for --sim-auth\n' "$(sim_sanitize "$1")" >&2
               sim_auth_usage; return 2 ;;
        esac
    done

    ki="${ki^^}"; rand="${rand^^}"; op="${op^^}"; opc="${opc^^}"
    top="${top^^}"; sqn="${sqn^^}"; amf="${amf^^}"

    local want_ki=32
    [[ "$algo" == tuak ]] && want_ki=$(( klength * 2 / 8 ))
    [[ "$ki" =~ ^[0-9A-F]+$ && ${#ki} -eq $want_ki ]] || {
        printf 'ERROR\tki must be %d hex digits for %s, got %d\n' \
            "$want_ki" "$algo" "${#ki}" >&2; return 2; }
    [[ "$rand" =~ ^[0-9A-F]{32}$ ]] || {
        printf 'ERROR\trand must be 32 hex digits (16 bytes), got %d\n' "${#rand}" >&2; return 2; }
    [[ "$klength" =~ ^(128|256)$ ]] || {
        printf 'ERROR\t--klength must be 128 or 256\n' >&2; return 2; }
    [[ "$iterations" =~ ^(1|2)$ ]] || {
        printf 'ERROR\t--iterations must be 1 or 2\n' >&2; return 2; }
    [[ -z "$sqn" || "$sqn" =~ ^[0-9A-F]{12}$ ]] || {
        printf 'ERROR\tsqn must be 12 hex digits (6 bytes), got %d\n' "${#sqn}" >&2; return 2; }
    [[ -z "$amf" || "$amf" =~ ^[0-9A-F]{4}$ ]] || {
        printf 'ERROR\tamf must be 4 hex digits (2 bytes), got %d\n' "${#amf}" >&2; return 2; }

    local tool raw
    tool=$(sim_dpa_tool) || return $?

    case "$algo" in
        comp128-1|comp128-2|comp128-3)
            local v="${algo#comp128-}"
            raw=$(python3 "$tool" --comp128 "v$v" --ki "$ki" --rand "$rand") || return 1
            printf 'algorithm\t%s\n' "$algo"
            printf 'ki\t%s\n'   "$ki"
            printf 'rand\t%s\n' "$rand"
            printf 'sres\t%s\n' "$(sim_kv sres "$raw")"
            printf 'kc\t%s\n'   "$(sim_kv kc "$raw")"
            printf 'source\ttools/gsm_crypto.py --comp128 v%s (computed in a subprocess)\n' "$v"
            printf 'limit\tCOMP128 defines SRES (4 B) and Kc (8 B) only: no CK/IK, no AUTN, no SQN/AMF input, so no UMTS AKA vector exists for it\n'
            return 0 ;;
        milenage)
            if [[ -n "$op" && -n "$opc" ]]; then
                printf 'ERROR\tgive --op or --opc, not both: OPc is derived from OP when only OP is given\n' >&2
                return 2
            fi
            if [[ -n "$opc" ]]; then
                [[ "$opc" =~ ^[0-9A-F]{32}$ ]] || {
                    printf 'ERROR\t--opc must be 32 hex digits (16 bytes)\n' >&2; return 2; }
            else
                [[ "$op" =~ ^[0-9A-F]{32}$ ]] || {
                    printf 'ERROR\t--op must be 32 hex digits (16 bytes), or pass --opc\n' >&2
                    return 2; }
            fi
            local -a margs=(--milenage --ki "$ki" --rand "$rand")
            if [[ -n "$opc" ]]; then margs+=(--opc "$opc"); else margs+=(--op "$op"); fi
            [[ -n "$sqn" ]] && margs+=(--sqn "$sqn")
            [[ -n "$amf" ]] && margs+=(--amf "$amf")
            raw=$(python3 "$tool" "${margs[@]}") || return 1
            printf 'algorithm\tmilenage\n'
            printf 'ki\t%s\n'   "$ki"
            printf 'rand\t%s\n' "$rand"
            [[ -n "$op" ]] && printf 'op\t%s\n' "$op"
            printf 'opc\t%s\n' "$(sim_kv opc "$raw")"
            sim_auth_umts_rows "$raw" "$sqn" "$amf"
            printf 'source\ttools/gsm_crypto.py --milenage (computed in a subprocess)\n'
            printf 'limit\tthe tool emits f1..f5* and never AUTN or AUTS; K is 128-bit only, f2/f3/f4 are 128-bit and f1 64-bit (TS 35.206 defaults) with no option to change the output lengths\n'
            printf 'limit\taes128_enc (FIPS-197) is a library function in tools/gsm_crypto.py with no CLI verb, so it is exercised here only through Milenage\n'
            printf 'limit\tthis run emits f1..f5*; the AUTN is assembled by --sim-auth from them, and the AUTS side of a resync is --auts-build (card) / --auts-verify (network)\n'
            return 0 ;;
        tuak)
            [[ "$top" =~ ^[0-9A-F]{64}$ ]] || {
                printf 'ERROR\t--top must be 64 hex digits (the TUAK TOP, not an OP), got %d\n' "${#top}" >&2
                return 2; }
            local -a targs=(--tuak --ki "$ki" --rand "$rand" --top "$top"
                            --klength "$klength" --iterations "$iterations")
            [[ -n "$sqn" ]] && targs+=(--sqn "$sqn")
            [[ -n "$amf" ]] && targs+=(--amf "$amf")
            raw=$(python3 "$tool" "${targs[@]}") || return 1
            printf 'algorithm\ttuak\n'
            printf 'ki\t%s\n'   "$ki"
            printf 'rand\t%s\n' "$rand"
            printf 'top\t%s\n'  "$top"
            printf 'topc\t%s\n' "$(sim_kv topc "$raw")"
            printf 'keccak_iterations\t%s\n' "$(sim_kv keccak_iterations "$raw")"
            printf 'key_bits\t%s\n' "$klength"
            sim_auth_umts_rows "$raw" "$sqn" "$amf"
            printf 'source\ttools/gsm_crypto.py --tuak (computed in a subprocess)\n'
            printf 'limit\tTUAK MAC_sz/RES_sz/CK_sz/IK_sz are per-vector parameters, not fixed by the algorithm: this verb passes --mac-sz 64 --res-sz 64 --ck-sz 128 --ik-sz 128, and the tool prints the sizes it used in mac_sz/res_sz/ck_sz/ik_sz rows; pass --res-sz 32 through to match a TS 35.232 row posed for a 32-bit RES, which changes f2/f3/f4/f5; AUTN is assembled above, AUTS is not built\n'
            return 0 ;;
    esac
    sim_auth_usage
    return 2
}

# --sim-auth-check : published known-answer vectors through the module's own
# verb (so the delegation, the parsing and the arithmetic are all covered).
#
# Provenance is in the row name:
#   std-*   the value is fixed by the 3GPP document named in the row
#   tool-*  the value is the tool's own table (tools/gsm_crypto.py); the tool
#           attributes the row to a spec that this build could not re-read, so
#           it is labelled tool-sourced rather than standard-sourced
sim_cmd_sim_auth_check() {
    local bad=0 tool out
    # Printed, not returned: the caller counts with its own `bad`, so a KAT
    # helper called from the module selftest must not shadow chk.
    kat() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    tool=$(sim_dpa_tool) || return $?

    # TS 35.208 test set 1 (Milenage). K, RAND, SQN, AMF, OP, OPc, f1, f1*,
    # f2, f3, f4, f5, f5* are the values the standard fixes for that set.
    if out=$(sim_cmd_sim_auth milenage \
            465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 \
            --op CDC202D5123E20F62B6D676AC72CB318 --sqn FF9BB4D0B607 --amf B9B9); then
        kat std-ts35208-set1-opc     "$(sim_kv opc "$out")"   "CD63CB71954A9F4E48A5994E37A02BAF"
        kat std-ts35208-set1-f1      "$(sim_kv f1 "$out")"    "4A9FFAC354DFAFB3"
        kat std-ts35208-set1-f1star  "$(sim_kv 'f1*' "$out")" "01CFAF9EC4E871E9"
        kat std-ts35208-set1-f2      "$(sim_kv f2 "$out")"    "A54211D5E3BA50BF"
        kat std-ts35208-set1-f3      "$(sim_kv f3 "$out")"    "B40BA9A3C58B2A05BBF0D987B21BF8CB"
        kat std-ts35208-set1-f4      "$(sim_kv f4 "$out")"    "F769BCD751044604127672711C6D3441"
        kat std-ts35208-set1-f5      "$(sim_kv f5 "$out")"    "AA689C648370"
        kat std-ts35208-set1-f5star  "$(sim_kv 'f5*' "$out")" "451E8BECA43B"
        # AUTN for that set: (SQN xor f5) || AMF || f1, i.e. the XOR of two
        # values asserted above. Hand-checkable, and wrong if either f1 or f5
        # is wrong.
        kat std-ts35208-set1-autn    "$(sim_kv autn "$out")"  "55F328B43577B9B94A9FFAC354DFAFB3"
    else
        printf '%s\tFAIL milenage run failed\n' "std-ts35208-set1"; bad=$((bad + 1))
    fi

    # COMP128 test values, from the tool's tables: COMP128 is a GSMA algorithm
    # and this build found no 3GPP clause that fixes these numbers, so they are
    # labelled tool-sourced. v2 and v3 share SRES here and differ only in the
    # tail of Kc, which is exactly what the rows below pin.
    if out=$(sim_cmd_sim_auth comp128-1 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF); then
        kat tool-comp128v1-tv1-sres "$(sim_kv sres "$out")" "04A66BA8"
        kat tool-comp128v1-tv1-kc   "$(sim_kv kc "$out")"   "F87EB8222CEA3400"
    else
        printf '%s\tFAIL comp128-1 run failed\n' "tool-comp128v1-tv1"; bad=$((bad + 1))
    fi
    if out=$(sim_cmd_sim_auth comp128-2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 00000000000000000000000000000000); then
        kat tool-comp128v2-tv1-sres "$(sim_kv sres "$out")" "34B4225B"
        kat tool-comp128v2-tv1-kc   "$(sim_kv kc "$out")"   "F16B96E118A85800"
    else
        printf '%s\tFAIL comp128-2 run failed\n' "tool-comp128v2-tv1"; bad=$((bad + 1))
    fi
    if out=$(sim_cmd_sim_auth comp128-3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 00000000000000000000000000000000); then
        kat tool-comp128v3-tv1-sres "$(sim_kv sres "$out")" "34B4225B"
        kat tool-comp128v3-tv1-kc   "$(sim_kv kc "$out")"   "F16B96E118A85986"
    else
        printf '%s\tFAIL comp128-3 run failed\n' "tool-comp128v3-tv1"; bad=$((bad + 1))
    fi

    # TUAK, from the tool's tables (it attributes them to TS 35.232 clause 6/7;
    # this build could not re-read that clause, so: tool-sourced).
    if out=$(sim_cmd_sim_auth tuak \
            ABABABABABABABABABABABABABABABAB 42424242424242424242424242424242 \
            --top 5555555555555555555555555555555555555555555555555555555555555555 \
            --sqn 111111111111 --amf FFFF); then
        # topc, f1, f1* and f5* do not depend on the RES length, so the CLI
        # reproduces the table row for them exactly.
        kat tool-tuak-tv1-topc   "$(sim_kv topc "$out")"   "BD04D9530E87513C5D837AC2AD954623A8E2330C115305A73EB45D1F40CCCBFF"
        kat tool-tuak-tv1-f1     "$(sim_kv f1 "$out")"     "F9A54E6AEAA8618D"
        kat tool-tuak-tv1-f1star "$(sim_kv 'f1*' "$out")"  "E94B4DC6C7297DF3"
        kat tool-tuak-tv1-f5star "$(sim_kv 'f5*' "$out")"  "E7AF6B3D0E38"
        # f2/f3/f4/f5 come out of one fused permutation whose field offsets
        # depend on RES_sz, which TS 35.232 sets per test row rather than fixing
        # in the algorithm. This verb passes the 64-bit sizes it has always
        # passed, so these four rows pin the delegation as it is used; the same
        # tool with --res-sz 32 reproduces the 32-bit RES row, asserted below.
        kat cli-tuak-res64-f2    "$(sim_kv f2 "$out")"     "7ABD06D3FFF7F634"
        kat cli-tuak-res64-f3    "$(sim_kv f3 "$out")"     "144269A4BD882A02026DDBB13243404B"
        kat cli-tuak-res64-f4    "$(sim_kv f4 "$out")"     "52C2ECDCB90878D9EAA7AE82ADD046C0"
        kat cli-tuak-res64-f5    "$(sim_kv f5 "$out")"     "AAD217459A65"
        kat cli-tuak-sizes       "$(printf '%s %s %s %s' "$(sim_kv mac_sz "$out")" "$(sim_kv res_sz "$out")" "$(sim_kv ck_sz "$out")" "$(sim_kv ik_sz "$out")")" "64 64 128 128"
        # The TS 35.232 row's own sizes, reachable only because the CLI now
        # takes them: RES_sz 32 moves f2..f5 and must move exactly these way.
        out32=$(python3 "$IMSISTING_ROOT/tools/gsm_crypto.py" --tuak \
            --ki ABABABABABABABABABABABABABABABAB \
            --top 5555555555555555555555555555555555555555555555555555555555555555 \
            --rand 42424242424242424242424242424242 \
            --sqn 111111111111 --amf FFFF --res-sz 32 2>/dev/null)
        kat std-tuak-res32-f2    "$(sim_kv f2 "$out32")"   "657ACD64"
        kat std-tuak-res32-f3    "$(sim_kv f3 "$out32")"   "D71A1E5C6CAFFE986A26F783E5C78BE1"
        kat std-tuak-res32-f4    "$(sim_kv f4 "$out32")"   "BE849FA2564F869AECEE6F62D4337E72"
        kat std-tuak-res32-f5    "$(sim_kv f5 "$out32")"   "719F1E9B9054"
    else
        printf '%s\tFAIL tuak run failed\n' "tool-tuak-tv1"; bad=$((bad + 1))
    fi
    printf 'note\tTUAK f2/f3/f4/f5 above are the sizes this verb passes (RES_sz 64); the TS 35.232 row uses RES_sz 32, which the tool reproduces when given --res-sz 32, and the selftest asserts both paths\n'

    # A wrong input length must be refused, not zero-filled.
    kat auth-rejects-short-ki "$(sim_cmd_sim_auth comp128-1 0011 00112233445566778899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "2"
    kat auth-rejects-unknown  "$(sim_cmd_sim_auth comp128-9 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "2"
    kat auth-rejects-no-sqn-rand "$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 >/dev/null 2>&1; echo $?)" "2"

    # The card side runs last: it authenticates against the same store, and
    # an AUTHENTICATE here legitimately moves SQN, so anything asserted
    # after it would be asserting this test's own side effect.
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── SGP.22 ES9+ request builder (LPA -> SM-DP+) ─────────────────────────
# WHAT IS REAL: the request line, the headers SGP.22 mandates, and the JSON
# body for the four synchronous ES9+ functions, built to the field sets in
# SGP.22 v2.2.2 6.5.2.6..6.5.2.10 with the HTTP framing from 6.5.1. The bytes
# are deterministic: keys in the order the schema lists them, no whitespace, no
# escaping, so the JSON can be compared byte for byte.
#
# WHAT IS NOT: nothing is sent (no socket, no TLS, no HTTP client). ES2+ and
# ES10b/ES10c are NOT implemented - the DER payloads are passed through
# verbatim and have to come from an ES10 run against a real eUICC.

sim_es9_b64() { # hex -> base64
    python3 -c 'import base64,sys; sys.stdout.write(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' \
        "${1:-}"
}

sim_es9_plus_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --es9-plus <op> --smds <host[:port]> [flags]
  ops (SGP.22 v2.2.2 6.5.2.6..6.5.2.10):
    initiateAuthentication   --euicc-challenge <32 hex> --euicc-info1 <DER hex> [--smdp-address <fqdn>]
    authenticateClient       --transaction-id <hex> --authenticate-server-response <DER hex>
    getBoundProfilePackage   --transaction-id <hex> --prepare-download-response <DER hex>
    cancelSession            --transaction-id <hex> --cancel-session-response <DER hex>
  accepted and announced as not-emitted: --eid --matching-id --server-challenge --client-challenge
  --out <path>   write the curl command to a file
EOF
}

sim_cmd_es9_plus() {
    local op="${1:-}"
    shift 2>/dev/null || true
    local fn method=POST path spec_clause
    case "$op" in
        initiateAuthentication|initiate-authentication|initiateAuthentication )
            fn="ES9+.InitiateAuthentication"
            path=/gsma/rsp2/es9plus/initiateAuthentication
            spec_clause="SGP.22 v2.2.2 6.5.2.6 (request schema), 5.6.1 (procedure); fields euiccChallenge, euiccInfo1, smdpAddress" ;;
        authenticateClient|authenticate-client )
            fn="ES9+.AuthenticateClient"
            path=/gsma/rsp2/es9plus/authenticateClient
            spec_clause="SGP.22 v2.2.2 6.5.2.8 (request schema), 5.6.3 (procedure); fields transactionId, authenticateServerResponse" ;;
        getBoundProfilePackage|get-bound-profile-package )
            fn="ES9+.GetBoundProfilePackage"
            path=/gsma/rsp2/es9plus/getBoundProfilePackage
            spec_clause="SGP.22 v2.2.2 6.5.2.7 (request schema), 5.6.2 (procedure); fields transactionId, prepareDownloadResponse" ;;
        cancelSession|cancel-session )
            fn="ES9+.CancelSession"
            path=/gsma/rsp2/es9plus/cancelSession
            spec_clause="SGP.22 v2.2.2 6.5.2.10 (request schema), 5.6.5 (procedure); fields transactionId, cancelSessionResponse" ;;
        handleNotification|handle-notification )
            printf 'ERROR\thandleNotification (SGP.22 v2.2.2 6.5.2.9 ES9+.HandleNotification) is not built by this module: it belongs to the notification flow, not to the four profile-download functions (5.6.1..5.6.3, 5.6.5). Nothing is emitted\n' >&2
            return 2 ;;
        '') sim_es9_plus_usage; return 2 ;;
        *)  printf 'ERROR\tunknown ES9+ operation %s; built: initiateAuthentication, authenticateClient, getBoundProfilePackage, cancelSession\n' \
                "$(sim_sanitize "$op")" >&2
            return 2 ;;
    esac

    local smds='' eid='' mid='' txn='' schal='' cchal='' out_path=''
    local ec='' info1='' smdp_addr='' auth_resp='' prep_resp='' cancel_resp=''
    while (( $# )); do
        case "$1" in
            --smds)                     smds="${2:-}";      shift 2 2>/dev/null || shift ;;
            --eid)                      eid="${2:-}";       shift 2 2>/dev/null || shift ;;
            --matching-id)              mid="${2:-}";       shift 2 2>/dev/null || shift ;;
            --transaction-id)           txn="${2:-}";       shift 2 2>/dev/null || shift ;;
            --server-challenge)         schal="${2:-}";     shift 2 2>/dev/null || shift ;;
            --client-challenge)         cchal="${2:-}";     shift 2 2>/dev/null || shift ;;
            --euicc-challenge)          ec="${2:-}";        shift 2 2>/dev/null || shift ;;
            --euicc-info1)              info1="${2:-}";     shift 2 2>/dev/null || shift ;;
            --smdp-address)             smdp_addr="${2:-}"; shift 2 2>/dev/null || shift ;;
            --authenticate-server-response) auth_resp="${2:-}";   shift 2 2>/dev/null || shift ;;
            --prepare-download-response)    prep_resp="${2:-}";   shift 2 2>/dev/null || shift ;;
            --cancel-session-response)      cancel_resp="${2:-}"; shift 2 2>/dev/null || shift ;;
            --out)                      out_path="${2:-}";  shift 2 2>/dev/null || shift ;;
            *) printf 'ERROR\tunsupported flag %s for --es9-plus\n' "$(sim_sanitize "$1")" >&2
               sim_es9_plus_usage; return 2 ;;
        esac
    done

    [[ -n "$smds" ]] || {
        printf 'ERROR\t--es9-plus needs --smds <host[:port]>: SGP.22 6.5.1 the Host header and the HTTPS URL both come from it\n' >&2
        return 2; }
    [[ "$smds" =~ ^[A-Za-z0-9._:-]+$ ]] || {
        printf 'ERROR\t--smds must be a host or host:port, got %s\n' "$(sim_sanitize "$smds")" >&2
        return 2; }
    if [[ -n "$eid" ]]; then
        [[ "$eid" =~ ^[0-9A-Fa-f]{32}$ ]] || {
            printf 'ERROR\t--eid must be 32 hex digits\n' >&2; return 2; }
        eid="${eid^^}"
    fi
    [[ -z "$mid" || "$mid" =~ ^[A-Za-z0-9._-]+$ ]] || {
        printf 'ERROR\t--matching-id must be a plain identifier (A-Z a-z 0-9 . _ -)\n' >&2
        return 2; }

    local ec_b64='' info_b64='' resp_b64='' json=''
    case "$op" in
        initiateAuthentication|initiate-authentication)
            if [[ -n "$ec" && -n "$cchal" ]]; then
                printf 'ERROR\tgive --euicc-challenge or --client-challenge, not both: they are the same field (euiccChallenge)\n' >&2
                return 2
            fi
            ec="${ec:-$cchal}"
            [[ -n "$ec" ]] || {
                printf 'ERROR\tinitiateAuthentication needs --euicc-challenge <32 hex>: SGP.22 6.5.2.6 requires euiccChallenge, euiccInfo1 and smdpAddress\n' >&2
                return 2; }
            [[ "$ec" =~ ^[0-9A-Fa-f]{32}$ ]] || {
                printf 'ERROR\t--euicc-challenge must be 32 hex digits (16 bytes, the eUICC challenge from ES10b GetEUICCChallenge)\n' >&2
                return 2; }
            [[ -n "$info1" ]] || {
                printf 'ERROR\tinitiateAuthentication needs --euicc-info1 <DER hex>: SGP.22 6.5.2.6 requires euiccInfo1, base64-bound in the body\n' >&2
                return 2; }
            [[ "$info1" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#info1} % 2 == 0 )) || {
                printf 'ERROR\t--euicc-info1 must be an even number of hex digits (the DER EUICCInfo1)\n' >&2
                return 2; }
            smdp_addr="${smdp_addr:-${smds%%:*}}"
            [[ "$smdp_addr" =~ ^[A-Za-z0-9._-]+$ ]] || {
                printf 'ERROR\t--smdp-address must be the SM-DP+ FQDN\n' >&2; return 2; }
            ec="${ec^^}"; info1="${info1^^}"
            ec_b64=$(sim_es9_b64 "$ec") || return 1
            info_b64=$(sim_es9_b64 "$info1") || return 1
            json=$(printf '{"euiccChallenge":"%s","euiccInfo1":"%s","smdpAddress":"%s"}' \
                    "$ec_b64" "$info_b64" "$smdp_addr") ;;
        authenticateClient|authenticate-client|getBoundProfilePackage|get-bound-profile-package|cancelSession|cancel-session)
            [[ "$txn" =~ ^[0-9A-Fa-f]{2,32}$ ]] || {
                printf 'ERROR\t--transaction-id must be 2..32 hex digits (SGP.22 pattern ^[0-9,A-F]{2,32}$, uppercase on the wire; a lowercase input is transcoded)\n' >&2
                return 2; }
            txn="${txn^^}"
            case "$op" in
                authenticateClient|authenticate-client)
                    [[ -n "$auth_resp" ]] || {
                        printf 'ERROR\tauthenticateClient needs --authenticate-server-response <DER hex>: SGP.22 6.5.2.8 requires transactionId and authenticateServerResponse\n' >&2
                        return 2; }
                    [[ "$auth_resp" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#auth_resp} % 2 == 0 )) || {
                        printf 'ERROR\t--authenticate-server-response must be an even number of hex digits (the DER AuthenticateServerResponse)\n' >&2
                        return 2; }
                    resp_b64=$(sim_es9_b64 "${auth_resp^^}") || return 1
                    json=$(printf '{"transactionId":"%s","authenticateServerResponse":"%s"}' "$txn" "$resp_b64") ;;
                getBoundProfilePackage|get-bound-profile-package)
                    [[ -n "$prep_resp" ]] || {
                        printf 'ERROR\tgetBoundProfilePackage needs --prepare-download-response <DER hex>: SGP.22 6.5.2.7 requires transactionId and prepareDownloadResponse\n' >&2
                        return 2; }
                    [[ "$prep_resp" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#prep_resp} % 2 == 0 )) || {
                        printf 'ERROR\t--prepare-download-response must be an even number of hex digits (the DER PrepareDownloadResponse)\n' >&2
                        return 2; }
                    resp_b64=$(sim_es9_b64 "${prep_resp^^}") || return 1
                    json=$(printf '{"transactionId":"%s","prepareDownloadResponse":"%s"}' "$txn" "$resp_b64") ;;
                cancelSession|cancel-session)
                    [[ -n "$cancel_resp" ]] || {
                        printf 'ERROR\tcancelSession needs --cancel-session-response <DER hex>: SGP.22 6.5.2.10 requires transactionId and cancelSessionResponse\n' >&2
                        return 2; }
                    [[ "$cancel_resp" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#cancel_resp} % 2 == 0 )) || {
                        printf 'ERROR\t--cancel-session-response must be an even number of hex digits (the DER CancelSessionResponse)\n' >&2
                        return 2; }
                    resp_b64=$(sim_es9_b64 "${cancel_resp^^}") || return 1
                    json=$(printf '{"transactionId":"%s","cancelSessionResponse":"%s"}' "$txn" "$resp_b64") ;;
            esac ;;
        *)  printf 'ERROR\tinternal: unhandled operation %s\n' "$(sim_sanitize "$op")" >&2; return 3 ;;
    esac

    local url="https://${smds}${path}" clen=${#json} curl expects
    curl="curl -sS --http1.1 -X POST '${url}' -H 'Host: ${smds}' -H 'User-Agent: gsma-rsp-lpad' -H 'X-Admin-Protocol: gsma/rsp/v2.2.2' -H 'Content-Type: application/json' -H 'Content-Length: ${clen}' --data-binary '${json}'"
    case "$op" in
        initiateAuthentication|initiate-authentication)
            expects="200 + JSON: header.functionExecutionStatus, transactionId, serverSigned1, serverSignature1, euiccCiPKIdToBeUsed, serverCertificate (6.5.2.6)" ;;
        authenticateClient|authenticate-client)
            expects="200 + JSON: header.functionExecutionStatus, transactionId, profileMetadata, smdpSigned2, smdpSignature2, smdpCertificate (6.5.2.8; an SM-DS answers with the ES11.AuthenticateClient body instead)" ;;
        getBoundProfilePackage|get-bound-profile-package)
            expects="200 + JSON: header.functionExecutionStatus, transactionId, boundProfilePackage (6.5.2.7)" ;;
        cancelSession|cancel-session)
            expects="200 with no JSON body: 6.5.2.10 defines no response body for CancelSession" ;;
    esac

    printf 'scope\tSGP.22 ES9+ HTTP/JSON request builder; nothing is transmitted\n'
    printf 'spec\t%s\n' "$spec_clause"
    printf 'protocol_version\tgsma/rsp/v2.2.2 (6.2: the highest SGP.22 version supported by the sender; this builder implements v2.2.2)\n'
    printf 'function\t%s\n' "$fn"
    printf 'method\t%s\n' "$method"
    printf 'path\t%s\n' "$path"
    printf 'url\t%s\n' "$url"
    printf 'header_host\tHost: %s\n' "$smds"
    printf 'header_user_agent\tUser-Agent: gsma-rsp-lpad\n'
    printf 'header_admin_protocol\tX-Admin-Protocol: gsma/rsp/v2.2.2\n'
    printf 'header_content_type\tContent-Type: application/json\n'
    printf 'header_content_length\tContent-Length: %d\n' "$clen"
    printf 'body_bytes\t%d\n' "$clen"
    printf 'json\t%s\n' "$json"
    printf 'curl\t%s\n' "$curl"
    printf 'expects\t%s\n' "$expects"
    printf 'sent\t0\n'

    # Flags that look like they belong in an ES9+ body but do not. They are
    # announced, never silently dropped.
    [[ -n "$eid" ]] && printf 'limit\teid %s: not a field of any ES9+ v2.2.2 request body (6.5.2.6..6.5.2.10); the EID travels on ES2+ (6.5.2.1) and ES10c GetEID (5.7.20). Accepted, not emitted\n' "$eid"
    [[ -n "$mid" ]] && printf 'limit\tmatchingId %s: not a field of any ES9+ v2.2.2 request body; it is an ES2+ order field (6.5.2.1) and an ES10b AuthenticateServer input (5.7.13). Accepted, not emitted\n' "$mid"
    [[ -n "$schal" ]] && printf 'limit\tserverChallenge: an ES10b.AuthenticateServer input carried inside serverSigned1 (5.7.13), not an ES9+ request field. Accepted, not emitted\n'
    if [[ -n "$cchal" && ( "$op" == authenticateClient || "$op" == getBoundProfilePackage || "$op" == cancelSession || "$op" == authenticate-client || "$op" == get-bound-profile-package || "$op" == cancel-session ) ]]; then
        printf 'limit\tclientChallenge: not used by %s and the name does not appear in SGP.22 v2.2.2; for initiateAuthentication it is accepted as the euiccChallenge alias. Not emitted here\n' "$fn"
    fi
    [[ -n "$cchal" && ( "$op" == initiateAuthentication || "$op" == initiate-authentication ) ]] && \
        printf 'note\t--client-challenge is used as the eUICC challenge: the body field is euiccChallenge (6.5.2.6), and the name clientChallenge does not appear in SGP.22 v2.2.2\n'

    # A payload flag that belongs to a different operation is announced too:
    # silently ignoring a DER blob is how a builder lies about what it built.
    if [[ -n "$auth_resp" && "$op" != authenticateClient && "$op" != authenticate-client ]]; then
        printf 'limit\t--authenticate-server-response is %d hex digits but %s does not carry it (6.5.2.8 body only); not emitted\n' "${#auth_resp}" "$fn"
    fi
    if [[ -n "$prep_resp" && "$op" != getBoundProfilePackage && "$op" != get-bound-profile-package ]]; then
        printf 'limit\t--prepare-download-response is %d hex digits but %s does not carry it (6.5.2.7 body only); not emitted\n' "${#prep_resp}" "$fn"
    fi
    if [[ -n "$cancel_resp" && "$op" != cancelSession && "$op" != cancel-session ]]; then
        printf 'limit\t--cancel-session-response is %d hex digits but %s does not carry it (6.5.2.10 body only); not emitted\n' "${#cancel_resp}" "$fn"
    fi
    if [[ -n "$ec" && ( "$op" == authenticateClient || "$op" == authenticate-client || "$op" == getBoundProfilePackage || "$op" == get-bound-profile-package || "$op" == cancelSession || "$op" == cancel-session ) ]]; then
        printf 'limit\t--euicc-challenge is %d hex digits but only initiateAuthentication carries it (6.5.2.6 euiccChallenge); not emitted\n' "${#ec}"
    fi
    if [[ -n "$info1" && ( "$op" == authenticateClient || "$op" == authenticate-client || "$op" == getBoundProfilePackage || "$op" == get-bound-profile-package || "$op" == cancelSession || "$op" == cancel-session ) ]]; then
        printf 'limit\t--euicc-info1 is %d hex digits but only initiateAuthentication carries it (6.5.2.6 euiccInfo1); not emitted\n' "${#info1}"
    fi

    printf 'limit\tES9+ only: ES2+ (6.5.2.1..6.5.2.5) and ES10b/ES10c (5.7) are not implemented by this module, and neither is ES9+.HandleNotification (6.5.2.9)\n'
    printf 'limit\tthe DER payload is passed through verbatim: it has to come from an ES10b run (5.7.7 GetEUICCChallenge, 5.7.8 GetEUICCInfo, 5.7.13 AuthenticateServer, 5.7.5 PrepareDownload, 5.7.14 CancelSession); this verb checks hex syntax and nothing else\n'
    printf 'limit\tnothing is sent by this verb: no socket, no TLS, no HTTP client, no retry. `sent 0` is literal\n'

    if [[ -n "$out_path" ]]; then
        mkdir -p "$(dirname "$out_path")" 2>/dev/null
        {
            printf '#!/bin/sh\n'
            printf '# %s request, built by IMSIsting modules/16_sim.sh\n' "$fn"
            printf '# %s\n' "$spec_clause"
            printf '# sent 0 when written: running this file is what sends the request.\n'
            printf '%s\n' "$curl"
        } > "$out_path" || {
            printf 'ERROR\tcannot write %s\n' "$out_path" >&2; return 1; }
        printf 'out\t%s\n' "$out_path"
    fi
    return 0
}

# ── ES8+ / BPP — SM-DP+ to eUICC (SGP.22 v2.2.2 §5.5.1..§5.5.5) ─────────
# Every octet the builders emit is derived from a clause, and that clause is
# quoted in the `ref` row printed beside the value. The protection layer is
# NOT implemented: the '87'/'88'/'86' payloads are SCP03t-protected (§2.5.4,
# SGP.02 §2.6.4) and have to arrive already protected. Where the clause does
# not state an octet, the verb prints the field structure, names the missing
# clause in a `limit` row, and returns 3 (handoff) instead of 0.
sim_es8_len() { # value byte count -> BER length octets (short form, 81, 82, 83)
    local n="${1:-0}"
    if   (( n < 0x80 ));      then printf '%02X' "$n"
    elif (( n < 0x100 ));     then printf '81%02X' "$n"
    elif (( n < 0x10000 ));   then printf '82%04X' "$n"
    elif (( n < 0x1000000 )); then printf '83%06X' "$n"
    else return 1; fi
}

sim_es8_tlv() { # tag value-hex -> full TLV hex; empty + rc 1 on bad hex
    local tag="${1^^}" val="${2:-}"
    [[ "$tag" =~ ^([0-9A-F]{2})+$ ]] || return 1
    [[ -z "$val" || "$val" =~ ^([0-9A-F]{2})+$ ]] || return 1
    local l
    l=$(sim_es8_len $(( ${#val} / 2 ))) || return 1
    printf '%s%s%s' "$tag" "$l" "$val"
}

sim_es8_utf8hex() { # text -> UTF-8 octets as uppercase hex
    python3 -c 'import sys; sys.stdout.write(sys.argv[1].encode("utf-8").hex().upper())' \
        "${1:-}"
}

sim_es8_oidhex() { # dotted OID -> DER contents of the OBJECT IDENTIFIER (X.690 8.19)
    python3 -c '
import sys
try:
    arcs = [int(a) for a in sys.argv[1].strip().split(".")]
except ValueError:
    sys.exit(2)
if len(arcs) < 2 or arcs[0] < 0 or arcs[0] > 2 or arcs[1] < 0 or (arcs[0] < 2 and arcs[1] >= 40):
    sys.exit(3)
def b128(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append((v & 0x7f) | 0x80)
        v >>= 7
    return bytes(reversed(out))
print((b128(40 * arcs[0] + arcs[1]) + b"".join(b128(a) for a in arcs[2:])).hex().upper())
' "${1:-}"
}

sim_es8_bits() { # "ppr1 ppr2" -> BIT STRING value hex (unused-bits octet + bits)
    python3 -c '
import sys
ids = {"pprupdatecontrol": 0, "ppr1": 1, "ppr2": 2}
names = [n for n in sys.argv[1].replace(",", " ").split() if n]
try:
    bits = sorted({ids[n.lower()] for n in names})
except KeyError:
    sys.exit(2)
if not bits:
    sys.exit(3)
buf = bytearray(bits[-1] // 8 + 1)
for b in bits:
    buf[b // 8] |= 1 << (7 - b % 8)
sys.stdout.write("%02X%s" % (7 - bits[-1] % 8, buf.hex().upper()))
' "${1:-}"
}

# --es8-scp03t : build the SCP03t command TLVs around a profile-package segment
#
# SGP.02 v4.3 4.1.3.3: the profile package is protected by a secure channel
# that is SCP03 restricted to "MAC + encryption" (security level '33') and
# framed in TLVs instead of APDUs. The cryptography is inherited wholesale, so
# the keys, the chaining values and the KDF are the ones GPC Amendment D
# defines; what this command adds is the framing, the segment ceiling of 1024
# octets including tag and length, and the tags 84/85/86 and 9F44/9F45/9F46.
sim_cmd_es8_scp03t() {
    local k_enc='' k_mac='' host='' card='' kvn='30' payload='' card_crypt='' tool rows
    while (( $# )); do
        case "$1" in
            --k-enc)          k_enc="${2:-}";  shift 2 ;;
            --k-mac)          k_mac="${2:-}";  shift 2 ;;
            --host-challenge) host="${2:-}";   shift 2 ;;
            --card-challenge) card="${2:-}";   shift 2 ;;
            --kvn)            kvn="${2:-}";    shift 2 ;;
            --payload)        payload="${2:-}"; shift 2 ;;
            --card-cryptogram) card_crypt="${2:-}"; shift 2 ;;
            *)  printf 'ERROR\tunsupported flag %s for --es8-scp03t\n' "$(sim_sanitize "$1")" >&2
                return 2 ;;
        esac
    done
    tool="$IMSISTING_ROOT/tools/scp03t.py"
    if [[ ! -f "$tool" ]]; then
        printf 'ERROR\t%s is missing\n' "$tool" >&2; return 3
    fi
    local miss=''
    [[ -z "$k_enc" ]] && miss+="--k-enc "
    [[ -z "$k_mac" ]] && miss+="--k-mac "
    [[ -z "$host"  ]] && miss+="--host-challenge "
    [[ -z "$card"  ]] && miss+="--card-challenge "
    sim_es8_seg scp03t "the command TLVs a profile package travels in (SGP.02 4.1.3.3)"
    sim_es8_ref "SCP03t" "-" \
        "4.1.3.3: a secure channel protocol based on GlobalPlatform SCP03 usable for TLV structures; 'the SCP03 key sets are used for SCP03t'"
    sim_es8_ref "security level" "33" \
        "4.1.3.3: SHALL be '33' - C DECRYPTION, R ENCRYPTION, C MAC and R MAC, the only option SCP03t defines"
    sim_es8_ref "tags" "84 85 86" \
        "4.1.3.3: '84' INITIALIZE UPDATE, '85' EXTERNAL AUTHENTICATE, '86' the encrypted profile data; errors are the same tag +0x80, two octets (9F44, 9F45, 9F46)"
    if [[ -n "$miss" ]]; then
        sim_es8_limit "missing input: ${miss% }; a session needs both halves of the key set and both challenges. The card's half is what INITIALIZE UPDATE returns, so without a card it has to be supplied and is then taken on trust"
        sim_es8_handoff
        return 3
    fi
    if [[ -n "$card_crypt" ]]; then
        sim_is_hex "$card_crypt" || { printf 'ERROR\t--card-cryptogram is not hex\n' >&2; return 1; }
        (( ${#card_crypt} == 16 )) || {
            printf 'ERROR\tthe 84 response carries an 8-octet card cryptogram; got %d hex digits\n' \
                "${#card_crypt}" >&2
            return 1; }
    fi

    local k
    for k in "$k_enc" "$k_mac" "$host" "$card"; do
        if ! sim_is_hex "$k"; then
            printf 'ERROR\tkey or challenge is not hex\n' >&2; return 1
        fi
    done
    if (( ${#k_enc} != 32 || ${#k_mac} != 32 )); then
        printf 'ERROR\tSCP03 keys are 16 octets each; got %d and %d hex digits\n' \
            "${#k_enc}" "${#k_mac}" >&2
        return 1
    fi
    if (( ${#host} != 16 || ${#card} != 16 )); then
        printf 'ERROR\tboth challenges are 8 octets; got %d and %d hex digits\n' \
            "${#host}" "${#card}" >&2
        return 1
    fi
    rows=$(python3 "$tool" --derive --k-enc "${k_enc^^}" --k-mac "${k_mac^^}" \
               --host-challenge "${host^^}" --card-challenge "${card^^}" --kvn "${kvn^^}") || {
        printf 'ERROR\ttools/scp03t.py refused the key material\n' >&2; return 1; }
    printf '%s\n' "$rows" | while IFS=$'\t' read -r key value extra; do
        case "$key" in
            s_enc|s_mac|s_rmac|card_cryptogram|host_cryptogram) printf '%s\t%s\n' "$key" "$value" ;;
            tlv_84)                                              printf '%s\t%s\n' "$key" "$value" ;;
            # With a payload the '85' comes from the same run that MACs the
            # '86' TLVs; printing this one too would show the row twice.
            tlv_85) [[ -z "$payload" ]] && printf '%s\t%s\n' "$key" "$value" ;;
            ref)                                                 sim_es8_ref "derivation" "-" "$value" ;;
        esac
    done
    if [[ -n "$card_crypt" ]]; then
        # The derivation predicts the card cryptogram for these challenges; a
        # card that returned one is checked against that prediction rather
        # than believed. This is the verification R11 is about.
        local expected; expected=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="card_cryptogram"{print toupper($2); exit}')
        printf 'card_cryptogram_supplied\t%s\n' "${card_crypt^^}"
        printf 'card_cryptogram_expected\t%s\n' "$expected"
        if [[ "${card_crypt^^}" == "$expected" ]]; then
            printf 'card_cryptogram_matches\tyes\n'
            printf 'verdict\tthe supplied cryptogram is the one these keys and challenges derive: the channel is the one this session names\n'
        else
            printf 'card_cryptogram_matches\tno\n'
            printf 'verdict\tmismatch: the card is not running this key set, or the challenges are not the ones it saw\n'
            printf 'sent\t0\n'
            return 1
        fi
    fi
    if [[ -n "$payload" ]]; then
        sim_is_hex "$payload" || { printf 'ERROR\t--payload is not hex\n' >&2; return 1; }
        local count=0 wrapped
        # One run is one session, so the '85' MAC printed here is the one the
        # '86' MACs chain from; printing the '85' from a separate derivation
        # would put two unrelated MACs on adjacent rows.
        wrapped=$(python3 "$tool" --wrap "$payload" --k-enc "${k_enc^^}" --k-mac "${k_mac^^}" \
                      --host-challenge "${host^^}" --card-challenge "${card^^}") || {
            printf 'ERROR\ttools/scp03t.py could not protect the payload\n' >&2; return 1; }
        printf '%s\n' "$wrapped" | sed -n 's/^tlv_85[[:space:]]*\(.*\)$/tlv_85\t\1/p'
        printf '%s\n' "$wrapped" | while IFS=$'\t' read -r key value; do
            case "$key" in
                tlv_86_*) printf '%s\t%s\n' "$key" "$value" ;;
            esac
        done
        count=$(printf '%s\n' "$wrapped" | sed -n 's/^segments[[:space:]]*//p')
        sim_es8_field "command.count" "86" "INTEGER" "$count" \
            "4.1.3.3: each command TLV triggers one response TLV, and the package is split into segments of at most 1024 octets including tag and length"
        if (( count == 0 )); then
            sim_es8_limit "the payload did not fit one '86' TLV; segment the package first (tools/scp03t.py --unsegment)"
            sim_es8_handoff
            return 3
        fi
    else
        sim_es8_limit "no --payload: the session and the two initiation TLVs are built, the command TLVs are not"
    fi
    if [[ -n "$card_crypt" ]]; then
        sim_es8_limit "the challenges were supplied rather than negotiated: a match proves the key set and those challenges agree, not that a live card sent the cryptogram. Two independent implementations agreeing on the derivation is what tools/check-scp03t.sh establishes"
    else
        sim_es8_limit "no card here: the card challenge was supplied rather than negotiated, so card_cryptogram above is what the derivation predicts, not what a card confirmed -- pass --card-cryptogram to check one against it"
    fi
    sim_es8_ref "C-MAC" "-" \
        "GPC Amendment D 6.2: the MAC chaining value starts at 16 zero octets and each C-MAC becomes the next one; both are 8 octets in SCP03t mode 8"
    sim_es8_handoff
    return 0
}

sim_es8_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --es8-build <segment> [flags]
  ES8+ segments. Nesting and tags are the ones the clause text states; every
  value carries a `ref` row with the sentence it came from.
    bpp-header        BF36 { BF23 { ... } }  the BPP header (2.5.4)
        --transaction-id <2..32 hex>   TransactionId ::= OCTET STRING (SIZE(1..16))
        --host-id <2..32 hex>          controlRefTemplate.hostId, OctetTo16
        --smdp-otpk <130 hex>          smdpOtpk, 65 octets: 04 then the X point
        --smdp-sign <even hex>         smdpSign, the SM-DP+ signature
    initialise-secure-channel  BF23 alone, same flags (5.5.1)
    configure-isdp    BF24 { B8 { OBJECT IDENTIFIER } }   --dp-oid <a.b.c> (5.5.2)
    store-metadata    BF25 { 5A 91 92 93 94 95 B6 B7 99 }              (5.5.3)
        --iccid <20 hex>              iccid, Iccid as coded in EFiccid (5A)
        --service-provider-name <s>   serviceProviderName, UTF8String (SIZE(0..32)) (91)
        --profile-name <s>            profileName, UTF8String (SIZE(0..64)) (92)
        --icon-type jpg|png           iconType, INTEGER {jpg(0), png(1)} (93)
        --icon <hex>                  icon, OCTET STRING (SIZE(0..1024)) (94), needs --icon-type
        --profile-class test|provisioning|operational   profileClass (95)
        --profile-owner <6 hex>       profileOwner.mccMnc, TS 24.008 coding (B7)
        --ppr ppr1[,ppr2]             profilePolicyRules, PprIds BIT STRING (99)
        --notification install|enable|disable|delete=<fqdn>   notificationConfigurationInfo (B6)
    replace-session-keys  BF26 { 80 81 82 }   --mac-chaining --ppk-enc --ppk-cmac (5.5.4)
    sequence-87 --payload <hex>   A0 { '87' TLV(s) }   ConfigureISDP segment (2.5.4)
    sequence-88 --payload <hex>   A1 { '88' TLV(s) }   StoreMetadata segment (2.5.4)
    sequence-86 --payload <hex>   A3 { '86' TLV(s) }   profile element segment (2.5.4)
    bpp               BF36 { BF23 A0 A1 [A2] A3 }   --first-87 --88 --86 [--second-87]
  exit: 0 built  1 refused  2 usage  3 handoff (a clause the octets need is missing)
EOF
}

sim_es8_seg()   { printf 'segment\t%s\n' "$1"; printf 'spec\t%s\n' "$2"; }
sim_es8_ref()   { printf 'ref\t%s\t%s\t%s\n' "$1" "$2" "$3"; }
sim_es8_field() { printf 'field\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5"; }
sim_es8_limit() { printf 'limit\t%s\n' "$1"; }
sim_es8_note()  { printf 'note\t%s\n' "$1"; }
sim_es8_out() { # full TLV hex -> hex / bytes / status rows
    printf 'hex\t%s\n' "${1^^}"
    printf 'bytes\t%d\n' "$(( ${#1} / 2 ))"
    printf 'status\tbuilt\n'
}
sim_es8_handoff() { printf 'status\thandoff\n'; }

# The BF23 field structure, printed whether or not the octets could be built:
# this is the shape §5.5.1 states, in the order it states it.
sim_es8_bf23_fields() { # txn host otpk sign (placeholders allowed)
    sim_es8_field "BF23.remoteOpId" "82" "INTEGER" "01" \
        "5.5.1: remoteOpId (RemoteOpId ::= [2] INTEGER { installBoundProfilePackage(1) }); AUTOMATIC TAGS (Annex A) put the untagged member at [2], so 82 01 01"
    sim_es8_field "BF23.transactionId" "80" "OCTET STRING (SIZE(1..16))" "${1:-<from --transaction-id>}" \
        "5.5.1: transactionId [0] TransactionId"
    sim_es8_field "BF23.controlRefTemplate" "A6" "SEQUENCE" "-" \
        "5.5.1: controlRefTemplate [6] IMPLICIT ControlRefTemplate ([6] is constructed, so the identifier octet is A6)"
    sim_es8_field "BF23.controlRefTemplate.keyType" "80" "Octet1" "88" \
        "5.5.1: keyType [0] Octet1, AES='88'"
    sim_es8_field "BF23.controlRefTemplate.keyLen" "81" "Octet1" "10" \
        "5.5.1: keyLen [1] Octet1, shall be 0x10"
    sim_es8_field "BF23.controlRefTemplate.hostId" "84" "OctetTo16" "${2:-<from --host-id>}" \
        "5.5.1: hostId [4] OctetTo16"
    sim_es8_field "BF23.smdpOtpk" "5F49" "OCTET STRING" "${3:-<from --smdp-otpk>}" \
        "5.5.1: smdpOtpk [APPLICATION 73] OCTET STRING, tag '5F49'"
    sim_es8_field "BF23.smdpSign" "5F37" "OCTET STRING" "${4:-<from --smdp-sign>}" \
        "5.5.1: smdpSign [APPLICATION 55] OCTET STRING, tag '5F37'"
}

sim_es8_bf23_refs() {
    sim_es8_ref "BoundProfilePackage" "BF36" \
        "2.5.4: BoundProfilePackage ::= [54] SEQUENCE { -- Tag 0xBF36"
    sim_es8_ref "InitialiseSecureChannelRequest" "BF23" \
        "5.5.1: InitialiseSecureChannelRequest ::= [35] SEQUENCE { -- Tag 0xBF23"
    sim_es8_ref "remoteOpId" "82" \
        "5.5.1 RemoteOpId ::= [2] INTEGER { installBoundProfilePackage(1) } + Annex A AUTOMATIC TAGS => 82 01 01"
    sim_es8_ref "transactionId" "80" \
        "5.5.1: transactionId [0] TransactionId; TransactionId ::= OCTET STRING (SIZE(1..16))"
    sim_es8_ref "controlRefTemplate" "A6" \
        "5.5.1: controlRefTemplate [6] IMPLICIT ControlRefTemplate => 0xA6 (0x06 | constructed bit 0x20)"
    sim_es8_ref "keyType" "80" "5.5.1: keyType [0] Octet1, AES='88'"
    sim_es8_ref "keyLen" "81" "5.5.1: keyLen [1] Octet1, shall be 0x10"
    sim_es8_ref "hostId" "84" "5.5.1: hostId [4] OctetTo16"
    sim_es8_ref "smdpOtpk" "5F49" "5.5.1: smdpOtpk [APPLICATION 73] OCTET STRING, tag 0x5F49"
    sim_es8_ref "smdpSign" "5F37" "5.5.1: smdpSign [APPLICATION 55] OCTET STRING, tag 0x5F37"
    sim_es8_ref "length form" "BER" \
        "X.690 8.1.3: one length octet below 128, else 0x81/0x82/0x83 with that many length octets (the encoding inside a BPP is BER/DER, SGP.22 2.5.4)"
}

sim_cmd_es8_build() {
    local seg="${1:-}"
    shift 2>/dev/null || true
    local txn='' host='' otpk='' sign='' oid='' iccid='' spn='' pname='' pclass=''
    local itype='' icon='' owner='' ppr='' notif='' payload='' p87='' p88='' p87b='' p86=''
    local mac='' penc='' pcmac=''
    while (( $# )); do
        case "$1" in
            --transaction-id) txn="${2:-}";   shift 2 2>/dev/null || shift ;;
            --host-id)        host="${2:-}";  shift 2 2>/dev/null || shift ;;
            --mac-chaining)   mac="${2:-}";   shift 2 2>/dev/null || shift ;;
            --ppk-enc)        penc="${2:-}";  shift 2 2>/dev/null || shift ;;
            --ppk-cmac)       pcmac="${2:-}"; shift 2 2>/dev/null || shift ;;
            --smdp-otpk)      otpk="${2:-}";  shift 2 2>/dev/null || shift ;;
            --smdp-sign)      sign="${2:-}";  shift 2 2>/dev/null || shift ;;
            --dp-oid)         oid="${2:-}";   shift 2 2>/dev/null || shift ;;
            --iccid)          iccid="${2:-}"; shift 2 2>/dev/null || shift ;;
            --service-provider-name) spn="${2:-}"; shift 2 2>/dev/null || shift ;;
            --profile-name)   pname="${2:-}"; shift 2 2>/dev/null || shift ;;
            --profile-class)  pclass="${2:-}"; shift 2 2>/dev/null || shift ;;
            --icon-type)      itype="${2:-}"; shift 2 2>/dev/null || shift ;;
            --icon)           icon="${2:-}";  shift 2 2>/dev/null || shift ;;
            --profile-owner)  owner="${2:-}"; shift 2 2>/dev/null || shift ;;
            --ppr)            ppr="${2:-}";   shift 2 2>/dev/null || shift ;;
            --notification)   notif="${2:-}"; shift 2 2>/dev/null || shift ;;
            --payload)        payload="${2:-}"; shift 2 2>/dev/null || shift ;;
            --first-87)       p87="${2:-}";   shift 2 2>/dev/null || shift ;;
            --88)             p88="${2:-}";   shift 2 2>/dev/null || shift ;;
            --second-87)      p87b="${2:-}";  shift 2 2>/dev/null || shift ;;
            --86)             p86="${2:-}";   shift 2 2>/dev/null || shift ;;
            --help|-h)        sim_es8_usage; return 2 ;;
            '')               sim_es8_usage; return 2 ;;
            *) printf 'ERROR\tunsupported flag %s for --es8-build\n' "$(sim_sanitize "$1")" >&2
               return 2 ;;
        esac
    done

    local txn_n="${txn}" host_n="$host" otpk_n="$otpk" sign_n="$sign"
    [[ -z "$txn"  ]] || txn_n="${txn^^}"
    [[ -z "$host" ]] || host_n="${host^^}"
    [[ -z "$otpk" ]] || otpk_n="${otpk^^}"
    [[ -z "$sign" ]] || sign_n="${sign^^}"

    case "$seg" in
        bpp-header|initialise-secure-channel|initiate-secure-channel|bf23)
            local want_bpp=0
            [[ "$seg" == bpp-header ]] && want_bpp=1
            local segspec="ES8+.InitialiseSecureChannel (5.5.1)"
            (( want_bpp )) && segspec="ES8+.InitialiseSecureChannel (5.5.1) wrapped in the BoundProfilePackage header (2.5.4)"
            sim_es8_seg "$seg" "$segspec"
            if (( want_bpp )); then
                sim_es8_ref "BoundProfilePackage" "BF36" \
                    "2.5.4: BoundProfilePackage ::= [54] SEQUENCE { -- Tag 0xBF36 ... initialiseSecureChannelRequest [35] InitialiseSecureChannelRequest, -- Tag 0xBF23"
            fi
            sim_es8_bf23_refs
            sim_es8_bf23_fields "$txn_n" "$host_n" "$otpk_n" "$sign_n"

            # Refusals first: a wrong-length input is refused (rc 1), a missing
            # one is a handoff (rc 3) because nothing about the octets is unknown.
            if [[ -n "$txn" ]] && ! sim_is_hex "$txn"; then
                printf 'ERROR\ttransactionId is not hex: TransactionId ::= OCTET STRING (SIZE(1..16)) (5.5.1)\n' >&2
                return 1
            fi
            if [[ -n "$txn" ]] && (( ${#txn} < 2 || ${#txn} > 32 )); then
                printf 'ERROR\ttransactionId is %d hex digits: TransactionId ::= OCTET STRING (SIZE(1..16)) allows 1..16 octets (5.5.1)\n' "${#txn}" >&2
                return 1
            fi
            if [[ -n "$host" ]] && ! sim_is_hex "$host"; then
                printf 'ERROR\thostId is not hex: OctetTo16 (5.5.1)\n' >&2; return 1
            fi
            if [[ -n "$host" ]] && (( ${#host} > 32 )); then
                printf 'ERROR\thostId is %d hex digits: OctetTo16 allows 1..16 octets (5.5.1)\n' "${#host}" >&2
                return 1
            fi
            if [[ -n "$otpk" ]] && ! sim_is_hex "$otpk"; then
                printf 'ERROR\tsmdpOtpk is not hex\n' >&2; return 1
            fi
            if [[ -n "$otpk" ]] && (( ${#otpk} != 130 )); then
                printf 'ERROR\tsmdpOtpk is %d hex digits: an uncompressed P-256 point is 65 octets, 04 then X then Y (130 hex digits)\n' "${#otpk}" >&2
                return 1
            fi
            if [[ -n "$sign" ]] && ! sim_is_hex "$sign"; then
                printf 'ERROR\tsmdpSign is not hex\n' >&2; return 1
            fi
            if [[ -z "$txn" || -z "$host" || -z "$otpk" || -z "$sign" ]]; then
                local miss=''
                [[ -z "$txn"  ]] && miss+="--transaction-id "
                [[ -z "$host" ]] && miss+="--host-id "
                [[ -z "$otpk" ]] && miss+="--smdp-otpk "
                [[ -z "$sign" ]] && miss+="--smdp-sign "
                sim_es8_limit "missing input: ${miss% }; the field structure above is what 5.5.1 states, the octets are not emitted without every member"
                sim_es8_limit "the clause text gives no default for any member of InitialiseSecureChannelRequest (5.5.1), so there is nothing to invent"
                sim_es8_handoff
                return 3
            fi
            local crt val
            crt=$(sim_es8_tlv A6 "$(sim_es8_tlv 80 88)$(sim_es8_tlv 81 10)$(sim_es8_tlv 84 "$host")") || return 1
            val="$(sim_es8_tlv 82 01)$(sim_es8_tlv 80 "$txn")${crt}$(sim_es8_tlv 5F49 "$otpk")$(sim_es8_tlv 5F37 "$sign")"
            local bf23
            bf23=$(sim_es8_tlv BF23 "$val") || return 1
            sim_es8_note "smdpSign is emitted as supplied: 5.5.1 does not state the octet length of the signature, so none is imposed here"
            if (( want_bpp )); then
                sim_es8_out "$(sim_es8_tlv BF36 "$bf23")"
            else
                sim_es8_out "$bf23"
            fi
            return 0 ;;

        configure-isdp|config-isdp|bf24)
            sim_es8_seg "$seg" "ES8+.ConfigureISDP (5.5.2)"
            sim_es8_ref "ConfigureISDPRequest" "BF24" \
                "5.5.2: ConfigureISDPRequest ::= [36] SEQUENCE { -- Tag 0xBF24"
            sim_es8_ref "dpProprietaryData" "B8" \
                "5.5.2: dpProprietaryData [24] DpProprietaryData OPTIONAL -- Tag 0xB8 (maximum size including tag and length field: 128 bytes)"
            sim_es8_ref "dpOid" "06" \
                "5.5.2: DpProprietaryData ::= SEQUENCE { dpOid OBJECT IDENTIFIER; -- the DER contents of the OID are X.690 8.19 }"
            sim_es8_field "BF24.dpProprietaryData" "B8" "SEQUENCE (max 128 octets with tag+length)" \
                "$([[ -n "$oid" ]] && echo "set, dpOid $oid" || echo absent)" "5.5.2: OPTIONAL"
            sim_es8_field "BF24.dpProprietaryData.dpOid" "06" "OBJECT IDENTIFIER" \
                "${oid:-<from --dp-oid>}" "5.5.2: dpOid"
            local oidhex val
            if [[ -n "$oid" ]]; then
                if ! oidhex=$(sim_es8_oidhex "$oid"); then
                    printf 'ERROR\t--dp-oid %s is not a valid dotted OID (first arc 0..2, second < 40 when the first is 0 or 1); 5.5.2 types dpOid as OBJECT IDENTIFIER\n' \
                        "$(sim_sanitize "$oid")" >&2
                    return 2
                fi
                val=$(sim_es8_tlv B8 "$(sim_es8_tlv 06 "$oidhex")") || return 1
            else
                val=''
                sim_es8_note "dpProprietaryData is OPTIONAL (5.5.2): with no --dp-oid the only lawful encoding is the empty SEQUENCE"
            fi
            sim_es8_out "$(sim_es8_tlv BF24 "$val")"
            return 0 ;;

        store-metadata|bf25)
            sim_es8_seg "$seg" "ES8+.StoreMetadata (5.5.3)"
            sim_es8_ref "StoreMetadataRequest" "BF25" \
                "5.5.3: StoreMetadataRequest ::= [37] SEQUENCE { -- Tag 0xBF25"
            sim_es8_ref "iccid" "5A" \
                "5.5.3: iccid Iccid; Iccid ::= [APPLICATION 26] OCTET STRING (SIZE(10)) -- the ICCID as coded in EFiccid, corresponding tag is 0x5A"
            sim_es8_ref "serviceProviderName" "91" "5.5.3: serviceProviderName [17] UTF8String (SIZE(0..32)) -- Tag 0x91"
            sim_es8_ref "profileName" "92" "5.5.3: profileName [18] UTF8String (SIZE(0..64)) -- Tag 0x92"
            sim_es8_ref "iconType" "93" "5.5.3: iconType [19] IconType OPTIONAL -- Tag 0x93; IconType ::= INTEGER {jpg(0), png(1)}"
            sim_es8_ref "icon" "94" "5.5.3: icon [20] OCTET STRING (SIZE(0..1024)) OPTIONAL -- Tag 0x94"
            sim_es8_ref "profileClass" "95" "5.5.3: profileClass [21] ProfileClass DEFAULT operational -- Tag 0x95; ProfileClass ::= INTEGER {test(0), provisioning(1), operational(2)}"
            sim_es8_ref "profileOwner" "B7" "5.5.3: profileOwner [23] OperatorId OPTIONAL -- Tag 0xB7"
            sim_es8_ref "profilePolicyRules" "99" "5.5.3: profilePolicyRules [25] PprIds OPTIONAL -- Tag 0x99; PprIds ::= BIT STRING {pprUpdateControl(0), ppr1(1), ppr2(2)}"
            sim_es8_ref "notificationConfigurationInfo" "B6" \
                "5.5.3: notificationConfigurationInfo [22] SEQUENCE OF NotificationConfigurationInformation OPTIONAL -- no tag is printed in 5.5.3; B6 is what [22] constructed gives"
            sim_es8_field "BF25.iccid" "5A" "OCTET STRING (SIZE(10))" "${iccid:-<from --iccid>}" "5.5.3: mandatory member"
            sim_es8_field "BF25.serviceProviderName" "91" "UTF8String (SIZE(0..32))" "$([[ -n "$spn" ]] && echo set || echo absent)" "5.5.3"
            sim_es8_field "BF25.profileName" "92" "UTF8String (SIZE(0..64))" "$([[ -n "$pname" ]] && echo set || echo absent)" "5.5.3"
            sim_es8_field "BF25.iconType" "93" "INTEGER {jpg(0),png(1)}" "${itype:-absent}" "5.5.3 OPTIONAL"
            sim_es8_field "BF25.icon" "94" "OCTET STRING (SIZE(0..1024))" "$([[ -n "$icon" ]] && echo set || echo absent)" "5.5.3 OPTIONAL, shall only be present if iconType is present"
            sim_es8_field "BF25.profileClass" "95" "INTEGER {test(0),provisioning(1),operational(2)}" "${pclass:-absent (DEFAULT operational)}" "5.5.3 DEFAULT operational"
            sim_es8_field "BF25.profileOwner" "B7" "OperatorId" "${owner:-absent}" "5.5.3 OPTIONAL"
            sim_es8_field "BF25.profilePolicyRules" "99" "PprIds BIT STRING" "${ppr:-absent}" "5.5.3 OPTIONAL"
            sim_es8_field "BF25.notificationConfigurationInfo" "B6" "SEQUENCE OF NotificationConfigurationInformation" "${notif:-absent}" "5.5.3 OPTIONAL"

            if [[ -z "$iccid" ]]; then
                sim_es8_limit "missing input: --iccid; iccid is a mandatory member of StoreMetadataRequest (5.5.3), so the SEQUENCE cannot be built"
                sim_es8_handoff
                return 3
            fi
            if ! sim_is_hex "$iccid" || (( ${#iccid} != 20 )); then
                printf 'ERROR\ticcid is %d hex digits: Iccid ::= [APPLICATION 26] OCTET STRING (SIZE(10)) as coded in EFiccid (5.5.3), i.e. 20 hex digits\n' "${#iccid}" >&2
                return 1
            fi
            local pclass_hex=''
            case "$pclass" in
                '') ;;
                test)         pclass_hex=00 ;;
                provisioning) pclass_hex=01 ;;
                operational)  pclass_hex=02 ;;
                *) printf 'ERROR\t--profile-class %s: ProfileClass ::= INTEGER {test(0), provisioning(1), operational(2)} (5.5.3)\n' \
                       "$(sim_sanitize "$pclass")" >&2; return 2 ;;
            esac
            if [[ -n "$itype" && "$itype" != jpg && "$itype" != png ]]; then
                printf 'ERROR\t--icon-type %s: IconType ::= INTEGER {jpg(0), png(1)} (5.5.3)\n' \
                    "$(sim_sanitize "$itype")" >&2; return 2
            fi
            if [[ -n "$icon" && -z "$itype" ]]; then
                printf 'ERROR\t--icon given without --icon-type: 5.5.3 says the icon shall only be present if iconType is present\n' >&2
                return 1
            fi
            if [[ -n "$icon" ]] && ! sim_is_hex "$icon"; then
                printf 'ERROR\t--icon is not hex\n' >&2; return 1
            fi
            local val
            val=$(sim_es8_tlv 5A "$iccid") || return 1
            [[ -n "$spn" ]]   && val+=$(sim_es8_tlv 91 "$(sim_es8_utf8hex "$spn")")
            [[ -n "$pname" ]] && val+=$(sim_es8_tlv 92 "$(sim_es8_utf8hex "$pname")")
            if [[ -n "$itype" ]]; then
                [[ "$itype" == jpg ]] && val+=$(sim_es8_tlv 93 00) || val+=$(sim_es8_tlv 93 01)
            fi
            [[ -n "$icon" ]] && val+=$(sim_es8_tlv 94 "$icon")
            [[ -n "$pclass_hex" ]] && val+=$(sim_es8_tlv 95 "$pclass_hex")
            if [[ -n "$owner" ]]; then
                if ! sim_is_hex "$owner" || (( ${#owner} != 6 )); then
                    printf 'ERROR\t--profile-owner is %d hex digits: OperatorId.mccMnc is OCTET STRING (SIZE(3)) (5.5.3), 6 hex digits\n' "${#owner}" >&2
                    return 1
                fi
                val+=$(sim_es8_tlv B7 "$(sim_es8_tlv 80 "$owner")")
                sim_es8_note "profileOwner: OperatorId ::= SEQUENCE { mccMnc OCTET STRING (SIZE(3)) } (5.5.3) has no tag printed for mccMnc; 80 is the context tag Annex A AUTOMATIC TAGS assigns the untagged member"
            fi
            if [[ -n "$ppr" ]]; then
                local pprhex
                if ! pprhex=$(sim_es8_bits "$ppr"); then
                    printf 'ERROR\t--ppr %s: PprIds ::= BIT STRING {pprUpdateControl(0), ppr1(1), ppr2(2)} (5.5.3)\n' \
                        "$(sim_sanitize "$ppr")" >&2; return 2
                fi
                val+=$(sim_es8_tlv 99 "$pprhex")
            fi
            if [[ -n "$notif" ]]; then
                local evt="${notif%%=*}" fqdn="${notif#*=}"
                local evt_hex=''
                case "$evt" in
                    install) evt_hex=0780 ;;
                    enable)  evt_hex=0640 ;;
                    disable) evt_hex=0520 ;;
                    delete)  evt_hex=0410 ;;
                    *) printf 'ERROR\t--notification %s: NotificationEvent ::= BIT STRING {notificationInstall(0), notificationEnable(1), notificationDisable(2), notificationDelete(3)} (5.7.10)\n' \
                           "$(sim_sanitize "$notif")" >&2; return 2 ;;
                esac
                [[ "$notif" == *"="* ]] || { printf 'ERROR\t--notification needs <event>=<fqdn>\n' >&2; return 2; }
                val+=$(sim_es8_tlv B6 "$(sim_es8_tlv 30 "$(sim_es8_tlv 80 "$evt_hex")$(sim_es8_tlv 81 "$(sim_es8_utf8hex "$fqdn")")")")
                sim_es8_note "notificationConfigurationInfo: the SEQUENCE members of NotificationConfigurationInformation (5.5.3) carry no tags in the text; 80/81 are the Annex A AUTOMATIC TAGS assignment, the SEQUENCE itself keeps its universal tag 30"
            fi
            sim_es8_out "$(sim_es8_tlv BF25 "$val")"
            return 0 ;;

        replace-session-keys|bf26)
            sim_es8_seg "$seg" "ES8+.ReplaceSessionKeys (5.5.4)"
            sim_es8_ref "ReplaceSessionKeysRequest" "BF26" \
                "5.5.4: ReplaceSessionKeysRequest ::= [38] SEQUENCE { -- tag 0xBF26"
            sim_es8_ref "initialMacChainingValue" "80" \
                "5.5.4: initialMacChainingValue OCTET STRING (first member; no tag in the text, 80 is the Annex A AUTOMATIC TAGS assignment)"
            sim_es8_ref "ppkEnc" "81" "5.5.4: ppkEnc OCTET STRING (second member, context tag 81 by AUTOMATIC TAGS)"
            sim_es8_ref "ppkCmac" "82" "5.5.4: ppkCmac OCTET STRING (third member, context tag 82 by AUTOMATIC TAGS)"
            sim_es8_field "BF26.initialMacChainingValue" "80" "OCTET STRING" "${mac:-<from --mac-chaining>}" "5.5.4 first member"
            sim_es8_field "BF26.ppkEnc" "81" "OCTET STRING" "${penc:-<from --ppk-enc>}" "5.5.4 second member"
            sim_es8_field "BF26.ppkCmac" "82" "OCTET STRING" "${pcmac:-<from --ppk-cmac>}" "5.5.4 third member"
            local missk=''
            [[ -z "$mac"   ]] && missk+="--mac-chaining "
            [[ -z "$penc"  ]] && missk+="--ppk-enc "
            [[ -z "$pcmac" ]] && missk+="--ppk-cmac "
            if [[ -n "$missk" ]]; then
                sim_es8_limit "missing input: ${missk% }; 5.5.4 states no default for any of the three keys, and their sizes are not stated in 5.5.4 (16 octets in the SCP03t scheme, SGP.02 2.6.4)"
                sim_es8_handoff
                return 3
            fi
            local k
            for k in "$mac" "$penc" "$pcmac"; do
                if ! sim_is_hex "$k" || (( ${#k} != 32 )); then
                    printf 'ERROR	key material is %d hex digits: the SCP03t keys and the MAC chaining value are 16 octets (SGP.02 2.6.4); 5.5.4 itself states no length\n' "${#k}" >&2
                    return 1
                fi
            done
            sim_es8_out "$(sim_es8_tlv BF26 "$(sim_es8_tlv 80 "${mac^^}")$(sim_es8_tlv 81 "${penc^^}")$(sim_es8_tlv 82 "${pcmac^^}")")"
            return 0 ;;

        sequence-87|sequence-88|sequence-86|segments)
            local outer tag
            case "$seg" in
                sequence-87) outer=A0; tag=87 ;;
                sequence-88) outer=A1; tag=88 ;;
                *)           outer=A3; tag=86 ;;
            esac
            sim_es8_seg "$seg" "one BPP segment: A? { '<tag>' TLV(s) } (2.5.4)"
            sim_es8_ref "segment wrapper" "$outer" \
                "2.5.4: firstSequenceOf87 [0] / sequenceOf88 [1] / sequenceOf86 [3] of BoundProfilePackage (A0, A1, A3 constructed)"
            sim_es8_ref "SCP03t payload" "$tag" \
                "2.5.4: the SCP03t payload TLVs are tag '87' (ConfigureISDP), '88' (StoreMetadata), '86' (profile elements); their values are protected (§2.6.4 SGP.02) and are passed through"
            if [[ -z "$payload" ]]; then
                sim_es8_limit "missing input: --payload; the '$tag' payload is the SCP03t-protected command block (2.5.4, §2.6.4 SGP.02) and this module does not implement the protection"
                sim_es8_handoff
                return 3
            fi
            if ! sim_is_hex "$payload"; then
                printf 'ERROR\t--payload is not hex\n' >&2; return 1
            fi
            if [[ "${payload^^}" != "$tag"* ]]; then
                # A segment of tag '87'/'88'/'86' may hold only TLVs of that tag
                # (2.5.4). What the operator passed is a profile element that the
                # SCP03t layer has not touched yet, and SGP.22 does not fix those
                # octets (the protection is SGP.02, the element chain SIMalliance
                # [5]). Print the structure, emit nothing, hand off.
                sim_es8_field "segment.$tag" "$tag" "OCTET STRING" "<SCP03t-protected payload>" \
                    "2.5.4: the value of a '$tag' TLV is the SCP03t-protected command block"
                sim_es8_limit "payload starts with ${payload:0:2}: a profile element (BF24, BF25, BF26, profile header) is not a segment: SCP03t protection runs over it first, and that protection (SGP.02 SCP03t) is not implemented here, so the octets are not emitted"
                sim_es8_handoff
                return 3
            fi
            sim_es8_out "$(sim_es8_tlv "$outer" "${payload^^}")"
            return 0 ;;

        bpp|bound-profile-package)
            sim_es8_seg "$seg" "the whole Bound Profile Package (2.5.4)"
            sim_es8_ref "BoundProfilePackage" "BF36" \
                "2.5.4: BoundProfilePackage ::= [54] SEQUENCE { -- Tag 0xBF36; initialiseSecureChannelRequest [35] InitialiseSecureChannelRequest, firstSequenceOf87 [0], sequenceOf88 [1], secondSequenceOf87 [2] OPTIONAL, sequenceOf86 [3] }"
            sim_es8_ref "segment order" "-" \
                "2.5.4: TLV command for key agreement in clear; '87' ConfigureISDP; '88' StoreMetadata; optional '87' Profile Protection Keys; '86' profile element chain"
            sim_es8_bf23_refs
            sim_es8_bf23_fields "$txn_n" "$host_n" "$otpk_n" "$sign_n"
            local miss=''
            [[ -z "$txn" ]] && miss+="--transaction-id "
            [[ -z "$host" ]] && miss+="--host-id "
            [[ -z "$otpk" ]] && miss+="--smdp-otpk "
            [[ -z "$sign" ]] && miss+="--smdp-sign "
            [[ -z "$p87" ]] && miss+="--first-87 "
            [[ -z "$p88" ]] && miss+="--88 "
            [[ -z "$p86" ]] && miss+="--86 "
            if [[ -n "$miss" ]]; then
                sim_es8_limit "missing input: ${miss% }; the chain is printed as structure above, the octets are not emitted"
                sim_es8_handoff
                return 3
            fi
            local part='' crt='' bf23=''
            for part in "$txn" "$host" "$otpk" "$sign" "$p87" "$p88" "$p86" ${p87b:+$p87b}; do
                sim_is_hex "$part" || { printf 'ERROR\tnot hex: %s\n' "$(sim_sanitize "$part")" >&2; return 1; }
            done
            crt=$(sim_es8_tlv A6 "$(sim_es8_tlv 80 88)$(sim_es8_tlv 81 10)$(sim_es8_tlv 84 "$host")") || return 1
            bf23=$(sim_es8_tlv BF23 "$(sim_es8_tlv 82 01)$(sim_es8_tlv 80 "$txn")${crt}$(sim_es8_tlv 5F49 "$otpk")$(sim_es8_tlv 5F37 "$sign")") || return 1
            local inner="$bf23$(sim_es8_tlv A0 "$p87")$(sim_es8_tlv A1 "$p88")"
            [[ -n "$p87b" ]] && inner+="$(sim_es8_tlv A2 "$p87b")"
            inner+="$(sim_es8_tlv A3 "$p86")"
            sim_es8_out "$(sim_es8_tlv BF36 "$inner")"
            return 0 ;;

        '') sim_es8_usage; return 2 ;;
        *)  printf 'ERROR\tunknown --es8-build segment %s; built: bpp-header, initialise-secure-channel, configure-isdp, store-metadata, replace-session-keys, sequence-87, sequence-88, sequence-86, bpp\n' \
                "$(sim_sanitize "$seg")" >&2
            return 2 ;;
    esac
}

# ── TLV walker — the BPP / PendingNotification envelope, without a phone ──
# Names and clause numbers here are the ones §2.5.4, §5.5.1..§5.5.4, §5.7.9,
# §5.7.10 and Annex A state. Where a tag has no clause, the walker says so in
# a `limit` row and returns 3 rather than guessing a name for it.
sim_es8_walk() { # <hex> <bpp|pending> -> rows; rc 0 parsed / 1 malformed / 3 handoff
    python3 - "${1:-}" "${2:-bpp}" <<'PY'
import sys

hexs = (sys.argv[1] if len(sys.argv) > 1 else "").strip().replace(" ", "")
mode = sys.argv[2] if len(sys.argv) > 2 else "bpp"

def die(msg, rc=1):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(rc)

if not hexs:
    die("no hex: pass the TLV bytes as an even-length hex string", 2)
try:
    data = bytes.fromhex(hexs)
except ValueError:
    die("not an even-length hex string", 2)

NAMES = {
    "BF36": ("BoundProfilePackage", "2.5.4"),
    "BF23": ("InitialiseSecureChannelRequest", "5.5.1"),
    "BF24": ("ConfigureISDPRequest", "5.5.2"),
    "B8":   ("dpProprietaryData", "5.5.2"),
    "06":   ("OBJECT IDENTIFIER", "5.5.2 / X.690 8.19"),
    "BF25": ("StoreMetadataRequest", "5.5.3"),
    "5A":   ("iccid (Iccid, [APPLICATION 26] OCTET STRING)", "5.5.3"),
    "91":   ("serviceProviderName UTF8String", "5.5.3"),
    "92":   ("profileName UTF8String", "5.5.3"),
    "93":   ("iconType INTEGER {jpg(0),png(1)}", "5.5.3"),
    "94":   ("icon OCTET STRING", "5.5.3"),
    "95":   ("profileClass INTEGER {test(0),provisioning(1),operational(2)}", "5.5.3"),
    "B6":   ("notificationConfigurationInfo SEQUENCE OF NotificationConfigurationInformation", "5.5.3"),
    "B7":   ("profileOwner OperatorId", "5.5.3"),
    "99":   ("profilePolicyRules PprIds BIT STRING {pprUpdateControl(0),ppr1(1),ppr2(2)}", "5.5.3"),
    "BF26": ("ReplaceSessionKeysRequest", "5.5.4"),
    "A0":   ("BoundProfilePackage.firstSequenceOf87", "2.5.4"),
    "A1":   ("BoundProfilePackage.sequenceOf88", "2.5.4"),
    "A2":   ("BoundProfilePackage.secondSequenceOf87 (OPTIONAL)", "2.5.4"),
    "A3":   ("BoundProfilePackage.sequenceOf86", "2.5.4"),
    "87":   ("SCP03t payload '87' (ConfigureISDP)", "2.5.4"),
    "88":   ("SCP03t payload '88' (StoreMetadata)", "2.5.4"),
    "86":   ("SCP03t payload '86' (profile element)", "2.5.4"),
    "5F49": ("smdpOtpk [APPLICATION 73] OCTET STRING", "5.5.1"),
    "5F37": ("signature [APPLICATION 55] OCTET STRING", "5.5.1 / 5.7.9"),
    "A6":   ("controlRefTemplate [6]", "5.5.1"),
    "80":   ("context [0]", "no clause names this octet on its own"),
    "81":   ("context [1]", "no clause names this octet on its own"),
    "84":   ("context [4]", "5.5.1"),
    "04":   ("OCTET STRING", "X.690 8.7"),
    "02":   ("INTEGER", "X.690 8.3"),
    "03":   ("BIT STRING", "X.690 8.6"),
    "0C":   ("UTF8String", "X.690"),
    "30":   ("SEQUENCE", "X.690 8.9"),
    "BF37": ("ProfileInstallationResult [55]", "5.7.9"),
    "BF27": ("ProfileInstallationResultData [39]", "5.7.9"),
    "BF2F": ("NotificationMetadata [47]", "5.7.9 / 5.7.10"),
    "5F0F": ("aid [APPLICATION 15] OCTET STRING (SIZE(5..16))", "5.7.9"),
}
CTX = {
    "A6/80":  ("controlRefTemplate.keyType Octet1 (AES = '88')", "5.5.1"),
    "A6/81":  ("controlRefTemplate.keyLen Octet1 (shall be 0x10)", "5.5.1"),
    "A6/84":  ("controlRefTemplate.hostId OctetTo16", "5.5.1"),
    "BF23/82": ("remoteOpId (RemoteOpId ::= [2] INTEGER)", "5.5.1"),
    "BF23/80": ("transactionId [0] TransactionId OCTET STRING (SIZE(1..16))", "5.5.1"),
    "BF23/A6": ("controlRefTemplate [6] IMPLICIT", "5.5.1"),
    "BF23/5F49": ("smdpOtpk [APPLICATION 73]", "5.5.1"),
    "BF23/5F37": ("smdpSign [APPLICATION 55]", "5.5.1"),
    "BF26/80": ("initialMacChainingValue OCTET STRING", "5.5.4 member 1 (tag by AUTOMATIC TAGS, Annex A)"),
    "BF26/81": ("ppkEnc OCTET STRING", "5.5.4 member 2 (tag by AUTOMATIC TAGS, Annex A)"),
    "BF26/82": ("ppkCmac OCTET STRING", "5.5.4 member 3 (tag by AUTOMATIC TAGS, Annex A)"),
    "BF2F/80": ("seqNumber [0] INTEGER", "5.7.9"),
    "BF2F/81": ("profileManagementOperation [1] NotificationEvent (one bit set)", "5.7.9"),
    "BF2F/82": ("notificationAddress UTF8String", "5.7.9 (untagged member, [2] by AUTOMATIC TAGS)"),
    "BF2F/5A": ("iccid OPTIONAL (Iccid)", "5.7.9"),
    "BF27/80": ("transactionId [0] TransactionId", "5.7.9"),
    "BF27/BF2F": ("notificationMetadata [47] NotificationMetadata", "5.7.9"),
    "BF27/06": ("smdpOid OBJECT IDENTIFIER", "5.7.9"),
    "BF27/A2": ("finalResult [2] CHOICE {successResult, errorResult}", "5.7.9"),
    "BF37/BF27": ("profileInstallationResultData [39] ProfileInstallationResultData", "5.7.9"),
    "BF37/5F37": ("euiccSignPIR [APPLICATION 55] OCTET STRING", "5.7.9"),
    "BF37/BF27/A2/30": ("finalResult: SuccessResult/ErrorResult SEQUENCE", "5.7.9"),
    "BF37/BF27/A2/30/5F0F": ("successResult.aid [APPLICATION 15]", "5.7.9"),
    "BF37/BF27/A2/30/80": ("successResult.simaResponse OR errorResult.bppCommandId (same octet, decided by which alternative is present)", "5.7.9 + Annex A"),
    "BF37/BF27/A2/30/81": ("errorResult.errorReason INTEGER", "5.7.9"),
    "BF37/BF27/A2/30/82": ("errorResult.simaResponse OPTIONAL", "5.7.9"),
}

PPR = {0: "pprUpdateControl", 1: "ppr1", 2: "ppr2"}
NEVENT = {0: "notificationInstall", 1: "notificationEnable", 2: "notificationDisable", 3: "notificationDelete"}

def bits(v, names):
    if not v:
        return ""
    unused = v[0]
    body = int.from_bytes(v[1:], "big")
    total = len(v[1:]) * 8
    out = []
    for i in range(total - unused):
        if body & (1 << (total - 1 - i)):
            out.append(names.get(i, "bit%d" % i))
    return ",".join(out)

def oid(v):
    if not v:
        return ""
    first = v[0]
    arcs = [first // 40, first % 40] if first < 80 else [2, first - 80]
    val = 0
    for b in v[1:]:
        val = (val << 7) | (b & 0x7f)
        if not b & 0x80:
            arcs.append(val)
            val = 0
    return ".".join(str(a) for a in arcs)

def iccid(v):
    if len(v) != 10:
        return ""
    d = "".join("%02X" % b for b in v)
    s = "".join(d[i + 1] + d[i] for i in range(0, 20, 2))
    return s.rstrip("F")

def meaning(path, th, v):
    p = full_path(path, th)
    if th == "5A" and len(v) == 10:
        return "= ICCID %s" % iccid(v)
    if th == "95" and v:
        return "= " + {0: "test", 1: "provisioning", 2: "operational"}.get(v[0], "?")
    if th == "93" and v:
        return "= " + {0: "jpg", 1: "png"}.get(v[0], "?")
    if th == "99":
        return "= " + bits(v, PPR)
    if p.endswith("BF23/82") and v:
        return "= " + {1: "installBoundProfilePackage"}.get(v[0], "?")
    if p.endswith("A6/80") and v:
        return "= keyType AES" if v[0] == 0x88 else "= keyType 0x%02X" % v[0]
    if p.endswith("A6/81") and v:
        return "= keyLen %d octets" % v[0]
    if th == "06" and v:
        return "= " + oid(v)
    if p.endswith("BF2F/80") and v:
        return "= seqNumber %d" % int.from_bytes(v, "big")
    if p.endswith("BF2F/81"):
        return "= " + bits(v, NEVENT)
    return ""

def preview(v):
    h = v.hex().upper()
    return h if len(h) <= 40 else h[:40] + "..."

def tag_at(buf, i):
    if i >= len(buf):
        raise ValueError("tag octet missing at offset 0x%X" % i)
    start, b = i, buf[i]
    if (b & 0x1f) == 0x1f:
        i += 1
        while True:
            if i >= len(buf):
                raise ValueError("truncated multi-octet tag at 0x%X" % start)
            c = buf[i]
            i += 1
            if not c & 0x80:
                break
        if i - start > 4:
            raise ValueError("tag longer than 4 octets at 0x%X" % start)
    else:
        i += 1
    return buf[start:i].hex().upper(), b, i

def length_at(buf, i):
    if i >= len(buf):
        raise ValueError("length octet missing at offset 0x%X" % i)
    b = buf[i]
    if b < 0x80:
        return b, i + 1
    if b == 0x80:
        raise ValueError("indefinite length (0x80) at 0x%X: X.690 8.1.3.6 form, not used in a DER RSP object" % i)
    n = b & 0x7f
    if n > 4:
        raise ValueError("length-of-length %d at 0x%X: refusing to guess" % (n, i))
    return int.from_bytes(buf[i + 1:i + 1 + n], "big"), i + 1 + n

EXPECT = {"bpp": ("BF36", "BoundProfilePackage", "2.5.4"),
          "pending": ("BF37", "ProfileInstallationResult", "5.7.9")}
unknown = []
opaque = set()
handoff = 0
rows = 0

def full_path(path, th):
    return (path + "/" + th) if path else th

def name_of(path, th):
    full = full_path(path, th)
    if full in CTX:
        return CTX[full]
    tail = "/".join(full.split("/")[-2:])
    if tail in CTX:
        return CTX[tail]
    return NAMES.get(th)

def walk(start, end, depth, path):
    global rows
    i = start
    while i < end:
        off = i
        th, t0, j = tag_at(data, i)
        ln, k = length_at(data, j)
        if k + ln > end:
            raise ValueError("tag %s at 0x%X claims %d octets, only %d remain"
                             % (th, off, ln, max(0, end - k)))
        v = data[k:k + ln]
        nm = name_of(path, th)
        name, clause = nm if nm else ("?", "no clause in SGP.22 v2.2.2 2.5.4/5.5.x/5.7.9/5.7.10 names this octet")
        m = meaning(path, th, v)
        value = preview(v) + (" " + m if m else "")
        print("tlv\t%d\t%s\t%s\t%d\t%s\t%s\t%s" % (depth, path, th, ln, value, name, clause))
        rows += 1
        if not nm:
            unknown.append((path, th, "0x%X" % off))
        if th in ("87", "88", "86"):
            opaque.add(th)
        i = k + ln
        if (t0 & 0x20) and ln and th not in ("87", "88", "86"):
            walk(k, k + ln, depth + 1, full_path(path, th))
    return i

try:
    th, t0, j = tag_at(data, 0)
except ValueError as e:
    die(str(e))

ln, k = length_at(data, j)
root = EXPECT.get(mode, EXPECT["bpp"])
root_hex, root_name, root_clause = root
print("bytes\t%d" % len(data))
print("root\t%s\t%s\t%s" % (th, NAMES.get(th, ("?", root_clause))[0], NAMES.get(th, ("?", root_clause))[1]))
if mode == "pending" and th not in ("BF37", "30"):
    print("limit\troot tag %s: a PendingNotification is a CHOICE of 'BF37' ProfileInstallationResult or an untagged OtherSignedNotification SEQUENCE (5.7.10); this is neither" % th)
    handoff = 1
elif mode == "bpp" and th != root_hex:
    print("note\troot tag %s is a %s, not the BF36 BoundProfilePackage (2.5.4) a whole BPP is; walking it as given, every field still carries its clause" % (th, NAMES.get(th, ("?",))[0]))

try:
    end = walk(0, len(data), 0, "")
except ValueError as e:
    die(str(e))
if end < len(data):
    print("limit\t%d trailing octets after the first top-level TLV at 0x%X: a BPP is one BF36 (2.5.4)" % (len(data) - end, end))
    handoff = 1
if opaque:
    print("limit\ttag(s) %s are SCP03t payloads (2.5.4): their values are printed opaque; the plaintext inside needs S-ENC/S-CMAC from the eUICC session (2.6.4 SGP.02) and this walker does not have them" % ",".join(sorted(opaque)))
for path, th, off in unknown:
    print("limit\ttag %s at %s (depth %d): no clause in SGP.22 v2.2.2 2.5.4 / 5.5.x / 5.7.9 / 5.7.10 names it; Annex A declares EXTENSIBILITY IMPLIED, so a decoder may not report an error, but this walker does not name it" % (th, path, path.count("/")))
    handoff = 1
print("status\t%s" % ("handoff" if handoff else "parsed"))
sys.exit(3 if handoff else 0)
PY
}

sim_cmd_es8_parse() {
    local hex="${1:-}"
    [[ -z "$hex" ]] && {
        printf 'ERROR\tusage: --es8-parse <hex>   (a Bound Profile Package: the base64 boundProfilePackage response field, decoded; e.g. pipe it through base64 -d and xxd -p)\n' >&2
        return 2; }
    hex="${hex// /}"
    sim_is_hex "$hex" && [[ -n "$hex" ]] || {
        printf 'ERROR\t--es8-parse takes an even-length hex string\n' >&2; return 2; }
    printf 'op\tES8+ Bound Profile Package parse\n'
    printf 'spec\tSGP.22 v2.2.2 2.5.4 (BPP and segment tags), 5.5.1..5.5.4 (BF23..BF26), Annex A (AUTOMATIC TAGS, EXTENSIBILITY IMPLIED)\n'
    printf 'sent\t0\n'
    sim_es8_walk "$hex" bpp
}

# ── ES9+ response bodies + HandleNotification (SGP.22 §6.5.2.6..§6.5.2.10) ──
# --es9-plus builds the four synchronous requests. These two verbs read the
# other direction: the <JSON responseMessage> body, with the header object of
# §6.5.1.4, and the one ES9+ call the builder refuses (§6.5.2.9).
sim_es9_response_py() { # <op> <json> <expected-txn> -> rows; rc 0/1/2/3
    python3 - "${1:-}" "${2:-}" "${3:-}" <<'PY'
import base64, binascii, json, re, sys

ALIAS = {
    "initiateAuthentication": "initiateAuthentication", "initiate-authentication": "initiateAuthentication",
    "authenticateClient": "authenticateClient", "authenticate-client": "authenticateClient",
    "getBoundProfilePackage": "getBoundProfilePackage", "get-bound-profile-package": "getBoundProfilePackage",
    "cancelSession": "cancelSession", "cancel-session": "cancelSession",
}
SPEC = {
    "initiateAuthentication": dict(
        fn="ES9+.InitiateAuthentication", clause="6.5.2.6", path="initiateAuthentication",
        declared=["transactionId", "serverSigned1", "serverSignature1", "euiccCiPKIdToBeUsed", "serverCertificate"],
        required=["transactionId", "serverSigned1", "serverSignature1", "euiccCiPKIdToBeUsed", "serverCertificate"],
        b64=["serverSigned1", "serverSignature1", "euiccCiPKIdToBeUsed", "serverCertificate"]),
    "authenticateClient": dict(
        fn="ES9+.AuthenticateClient", clause="6.5.2.8", path="authenticateClient",
        declared=["transactionId", "profileMetadata", "smdpSigned2", "smdpSignature2", "smdpCertificate"],
        required=["transactionId", "profileMetadata", "smdpSigned2", "smdpSignature2", "smdpCertificate"],
        b64=["profileMetadata", "smdpSigned2", "smdpSignature2", "smdpCertificate"]),
    "getBoundProfilePackage": dict(
        fn="ES9+.GetBoundProfilePackage", clause="6.5.2.7", path="getBoundProfilePackage",
        declared=["transactionId", "boundProfilePackage"],
        required=["transactionId", "boundProfilePackage"],
        b64=["boundProfilePackage"]),
    "cancelSession": dict(
        fn="ES9+.CancelSession", clause="6.5.2.10", path="cancelSession",
        declared=[], required=[], b64=[]),
}

def die(msg, rc=1):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(rc)

op = sys.argv[1] if len(sys.argv) > 1 else ""
raw = sys.argv[2] if len(sys.argv) > 2 else ""
want = (sys.argv[3] if len(sys.argv) > 3 else "").strip().upper()

if op not in ALIAS:
    die("unknown ES9+ operation %s; parsed: %s" % (op, ", ".join(SPEC)), 2)
op = ALIAS[op]
sp = SPEC[op]

def s(v):
    t = str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return t if len(t) <= 200 else t[:200] + "..."

try:
    body = json.loads(raw)
except Exception as e:
    die("the input is not JSON: %s" % e)
if not isinstance(body, dict):
    die("the <JSON body> of an ES9+ response is a JSON object, not %s" % type(body).__name__)

hdr = body.get("header")
if not isinstance(hdr, dict):
    die("no header object: SGP.22 6.5.1.4 requires header.functionExecutionStatus, so this is not an ES9+ response body")
fes = hdr.get("functionExecutionStatus")
if not isinstance(fes, dict):
    die("header has no functionExecutionStatus object: 6.5.1.4 requires it")
st = fes.get("status")
if not isinstance(st, str) or not st:
    die("header.functionExecutionStatus.status missing: 6.5.1.4 required [\"status\"]")

print("op\t%s" % sp["fn"])
print("spec\tSGP.22 v2.2.2 %s response JSON schema; header object 6.5.1.4" % sp["clause"])
print("mep\tHTTP POST https://<smds>/gsma/rsp2/es9plus/%s" % sp["path"])
print("expects\tHTTP 200 with this JSON body (6.3: a normal request-response is 200 whatever the function status)")
print("schema\t%s\trequired %s"
      % (", ".join(sp["declared"]) or "(none: 6.5.2.10 defines no response body)",
         ", ".join(sp["required"]) or "(none)"))
print("header\tfunctionExecutionStatus.status\t%s\t6.5.1.4 required [status]: Executed-Success / Executed-WithWarning / Failed / Expired" % s(st))
if st not in ("Executed-Success", "Executed-WithWarning", "Failed", "Expired"):
    print("limit\tstatus %s is not one of the four values 6.5.1.4 lists; reported as given" % s(st))
scd = fes.get("statusCodeData")
scd_bad = 0
if isinstance(scd, dict):
    for k, cl in (("subjectCode", "required [subjectCode]"), ("reasonCode", "required [reasonCode]")):
        if k in scd:
            print("header\tfunctionExecutionStatus.statusCodeData.%s\t%s\t6.5.1.4 %s" % (k, s(scd[k]), cl))
        else:
            print("limit\tstatusCodeData carries no %s: 6.5.1.4 requires [subjectCode, reasonCode] whenever statusCodeData is present" % k)
            scd_bad = 1
    for k in ("subjectIdentifier", "message"):
        if k in scd:
            print("header\tfunctionExecutionStatus.statusCodeData.%s\t%s\t6.5.1.4" % (k, s(scd[k])))
elif st in ("Failed", "Expired"):
    print("limit\tstatus is %s but there is no statusCodeData object: 6.5.1.4 puts subjectCode/reasonCode there" % st)

handoff = scd_bad
seen = set()
for k in body:
    if k == "header":
        continue
    seen.add(k)
    v = body[k]
    if k == "transactionId":
        okpat = isinstance(v, str) and re.fullmatch(r"[0-9A-F]{2,32}", v) is not None
        print("field\ttransactionId\t%s\t6.5.2.x: hexadecimal TransactionID, pattern ^[0-9,A-F]{2,32}$%s"
              % (s(v), "" if okpat else " -- does not match the pattern"))
        if not okpat:
            print("limit\ttransactionId does not match ^[0-9,A-F]{2,32}$ (6.5.2.6..6.5.2.10)")
            handoff = 1
    elif k in sp["b64"]:
        if not isinstance(v, str):
            print("limit\t%s is not a JSON string: 6.5.2.x types every binary field as a base64 string" % k)
            handoff = 1
            continue
        try:
            b = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            die("%s is not valid base64 (6.5.2.x format: base64)" % k)
        print("field\t%s\tbase64, %d octets, begins %s\t6.5.2.x: base64 encoded binary data"
              % (k, len(b), b[:16].hex().upper()))
        if k == "boundProfilePackage":
            if b[:2] == bytes([0xBF, 0x36]):
                print("field\tboundProfilePackage.root\tBF36 BoundProfilePackage\t2.5.4 BoundProfilePackage ::= [54] SEQUENCE -- Tag 'BF36'")
                print("next\t--es8-parse <hex of boundProfilePackage> walks it without a phone")
            else:
                print("limit\tboundProfilePackage does not begin BF36: 2.5.4 types it [54] SEQUENCE, Tag 'BF36'")
                handoff = 1
        if k == "profileMetadata":
            if b[:2] == bytes([0xBF, 0x25]):
                print("field\tprofileMetadata.root\tBF25 StoreMetadataRequest\t5.5.3 [37] SEQUENCE; 6.5.2.8 describes this field as the StoreMetadataRequest data object")
                print("next\t--es8-parse <hex of profileMetadata> walks it")
            else:
                print("limit\tprofileMetadata does not begin BF25: 6.5.2.8 describes it as the StoreMetadataRequest of 5.5.3, Tag 'BF25'")
                handoff = 1
    else:
        print("limit\tkey %s is not in the %s schema (6.5.2.x); Annex A EXTENSIBILITY IMPLIED lets a decoder ignore it, this parser reports it"
              % (s(k), sp["clause"]))
        handoff = 1

for f in sp["required"]:
    if f not in seen:
        print("limit\trequired field %s missing (SGP.22 %s required list)" % (f, sp["clause"]))
        handoff = 1

txn = body.get("transactionId")
if want and isinstance(txn, str):
    if txn.upper() == want:
        print("match\ttransactionId\techoed %s equals the transactionId the request carried" % s(txn))
    else:
        print("match\ttransactionId\tMISMATCH: response echoes %s, request carried %s" % (s(txn), s(want)))
        sys.stderr.write("ERROR\ttransactionId mismatch: the response echoes %s, the request carried %s (SGP.22 5.6.1/5.6.2 tie the exchange to it)\n"
                         % (s(txn), s(want)))
        sys.exit(1)
elif want and txn is None:
    print("match\ttransactionId\tnothing to compare: this body carries no transactionId")
elif isinstance(txn, str):
    print("match\ttransactionId\tnot checked: no --transaction-id given; the body echoes %s" % s(txn))

if op == "cancelSession":
    extra = set(body) - {"header"}
    print("note\t6.5.2.10: the ES9+.CancelSession function has no JSON body part of the response, so the header is all that can be checked"
          + ("; unexpected keys are reported above" if extra else ""))
if st in ("Failed", "Expired"):
    print("note\tfunction execution status %s: the call reached the SM-DP+ and the function failed; subjectCode/reasonCode above say where" % st)

print("status\t%s" % ("handoff" if handoff else "parsed"))
sys.exit(3 if handoff else 0)
PY
}

sim_es9_response_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --es9-response <op> <json> [--transaction-id <hex>]
  ops (SGP.22 v2.2.2 6.5.2.6..6.5.2.10). <json> is the <JSON body> of the
  RESPONSE; @file reads it from a file. The header object (6.5.1.4) is required:
    initiateAuthentication  transactionId, serverSigned1, serverSignature1,
                            euiccCiPKIdToBeUsed, serverCertificate
    authenticateClient      transactionId, profileMetadata, smdpSigned2,
                            smdpSignature2, smdpCertificate
    getBoundProfilePackage  transactionId, boundProfilePackage  (BF36, 2.5.4)
    cancelSession           no body at all: the function has no JSON response (6.5.2.10)
  exit: 0 parsed  1 refused (no header / mismatch / not JSON)  2 usage  3 handoff
        (a required field is missing, or a blob does not start with its tag)
EOF
}

sim_cmd_es9_response() {
    local op="${1:-}" json="${2:-}"
    shift 2 2>/dev/null || true
    local want=''
    while (( $# )); do
        case "$1" in
            --transaction-id|--expect-transaction-id) want="${2:-}"; shift 2 2>/dev/null || shift ;;
            --help|-h) sim_es9_response_usage; return 2 ;;
            *) printf 'ERROR\tunsupported flag %s for --es9-response\n' "$(sim_sanitize "$1")" >&2
               return 2 ;;
        esac
    done
    if [[ -z "$op" || -z "$json" ]]; then
        sim_es9_response_usage
        return 2
    fi
    if [[ "$json" == @* ]]; then
        local f="${json#@}"
        [[ -f "$f" ]] || { printf 'ERROR\tno such file: %s\n' "$f" >&2; return 1; }
        json=$(cat "$f") || return 1
    fi
    sim_es9_response_py "$op" "$json" "$want"
}

sim_es9_notification_usage() {
    cat >&2 <<'EOF'
ERROR	usage: --es9-notification <json>   (@file reads the body from a file)
  The ES9+.HandleNotification <JSON body> (SGP.22 v2.2.2 6.5.2.9):
    {"pendingNotification": "<base64 of the PendingNotification, 5.7.10>"}
  The binary is walked as a TLV ((BF37 ProfileInstallationResult | 30
  OtherSignedNotification) inside A0/A1... of the LPA notification flow) and
  every field is printed with its clause. The response is 204 with an empty
  body (6.2, 6.3): there is no JSON response schema to parse (6.5.2.9).
  exit: 0 parsed  1 refused  2 usage  3 handoff (a TLV has no clause)
EOF
}

# ── RSP binding audit: would a replay or a redirect be noticed? (R10) ───
#
# SGP.22's remote SIM provisioning moves a profile over the internet. The
# protocol's protection is not secrecy of the conversation -- TLS carries it --
# but BINDING: the transactionId ties a response to its request, the SM-DP+
# signatures tie the command to the key it was issued under, and the EID ties
# the profile to one eUICC. An exchange that has all three is hard to move; one
# missing any of them is a profile that can be installed somewhere else.
#
# This audits a captured exchange against those three ties and says which one
# is missing, citing the clause that requires it. It never says "safe": it says
# what would have to be true for a replay to work.
sim_rsp_audit() {
    local json="" req="" eid="" op=""
    while (( $# > 0 )); do
        case "$1" in
            --request)     req="${2:-}";  shift 2 ;;
            --eid)         eid="${2:-}";  shift 2 ;;
            --op)          op="${2:-}";   shift 2 ;;
            --help|-h)
                printf 'ERROR\tusage: --rsp-audit <response-json> [--request <request-json>] [--eid <32 hex>] [--op <operation>]\n' >&2
                printf 'NOTE\t  the response is an ES9+ response body; --request is the matching request body (or @file)\n' >&2
                return 2 ;;
            --*) printf 'ERROR\tunsupported flag %s for --rsp-audit\n' "$(sim_sanitize "$1")" >&2; return 2 ;;
            *)
                [[ -z "$json" ]] || {
                    printf 'ERROR\t--rsp-audit takes one response body\n' >&2; return 2; }
                json="$1"; shift ;;
        esac
    done
    [[ -n "$json" ]] || {
        printf 'ERROR\tusage: --rsp-audit <response-json> [--request <request-json>] [--eid <32 hex>] [--op <operation>]\n' >&2
        return 2; }
    sim_rsp_audit_py "$json" "$req" "$eid" "$op"
}

sim_rsp_audit_py() {  # <response> <request> <eid> <op>
    python3 - "${1:-}" "${2:-}" "${3:-}" "${4:-}" <<'PY'
import json, re, sys

def load(s):
    if s.startswith("@"):
        with open(s[1:], encoding="utf-8") as f:
            return json.load(f)
    return json.loads(s)

def s(v):
    t = str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return t if len(t) <= 120 else t[:120] + "..."

resp_raw, req_raw, eid, op = sys.argv[1], sys.argv[2], sys.argv[3].strip().upper(), sys.argv[4]
try:
    resp = load(resp_raw)
except Exception as e:
    sys.stderr.write("ERROR\tthe response is not JSON: %s\n" % e)
    sys.exit(1)
if not isinstance(resp, dict):
    sys.stderr.write("ERROR\tthe response body is a JSON object\n")
    sys.exit(1)

print("audit\tRSP exchange binding")
print("spec\tSGP.22 v2.2.2 6.5.1.4 (header), 6.5.2.6-6.5.2.8 (ES9+ bodies)")

# Which operation this is: --op wins, else the fields present decide.
if not op:
    if "serverSigned1" in resp:
        op = "initiateAuthentication"
    elif "smdpSigned2" in resp:
        op = "authenticateClient"
    elif "boundProfilePackage" in resp:
        op = "getBoundProfilePackage"
    else:
        op = "unknown"
print("operation\t%s" % (op if op != "unknown" else "undetermined"))

findings = []
def finding(sev, text):
    findings.append((sev, text))

# 1. The transaction tie: a response belongs to the request that asked for it.
tid = resp.get("transactionId")
if not isinstance(tid, str) or not re.fullmatch(r"[0-9A-F]{2,32}", tid):
    finding("HIGH", "the response carries no usable transactionId (6.5.2.6-6.5.2.8 require TransactionID)")
    print("binding.transaction\tabsent")
else:
    print("binding.transaction\t%s" % tid)
    if req_raw:
        try:
            rq = load(req_raw)
        except Exception as e:
            sys.stderr.write("ERROR\tthe request is not JSON: %s\n" % e)
            sys.exit(1)
        rtid = rq.get("transactionId") if isinstance(rq, dict) else None
        print("binding.request_transaction\t%s" % (rtid or "absent"))
        if rtid is None:
            finding("HIGH", "the request has no transactionId to bind to, so any response matches it")
        elif str(rtid).upper() != tid.upper():
            finding("HIGH", "the response answers transaction %s, not the request's %s: this is the shape a redirected or replayed response takes" % (tid, rtid))

# 2. The signature tie: the command has to come from the SM-DP+ key.
if op == "initiateAuthentication":
    for field, clause in (("serverSigned1", "6.5.2.6"), ("serverSignature1", "6.5.2.6"),
                          ("euiccCiPKIdToBeUsed", "6.5.2.6"), ("serverCertificate", "6.5.2.6")):
        if field not in resp:
            finding("HIGH", "initiateAuthentication without %s (%s): nothing ties the command to the SM-DP+ key" % (field, clause))
    if "serverSigned1" in resp and "serverSignature1" in resp:
        print("binding.signature\tserverSigned1 + serverSignature1 present")
elif op == "authenticateClient":
    for field, clause in (("smdpSigned2", "6.5.2.8"), ("smdpSignature2", "6.5.2.8"),
                          ("smdpCertificate", "6.5.2.8")):
        if field not in resp:
            finding("MEDIUM", "authenticateClient without %s (%s): the profile metadata is unsigned" % (field, clause))
    if "smdpSigned2" in resp:
        print("binding.signature\tsmdpSigned2 + smdpSignature2 present")
elif op == "unknown":
    finding("MEDIUM", "the body carries none of the ES9+ operation field sets (serverSigned1, smdpSigned2, boundProfilePackage), so the signature tie cannot be checked at all: an unsigned body and a body whose operation is not recognized look the same here")
elif op == "getBoundProfilePackage":
    if "boundProfilePackage" not in resp:
        finding("HIGH", "getBoundProfilePackage without boundProfilePackage (6.5.2.7)")
    else:
        bpp = resp["boundProfilePackage"]
        if isinstance(bpp, str) and len(bpp) < 32:
            finding("MEDIUM", "boundProfilePackage is %d base64 characters, too short to carry a profile" % len(bpp))
        print("binding.profile\tboundProfilePackage present (%s characters)" % (len(bpp) if isinstance(bpp, str) else "?"))

# 3. The device tie: a profile is for one EID.
if eid:
    named = []
    meta = resp.get("profileMetadata")
    if isinstance(meta, dict):
        for k in ("eidValue", "eid", "associationToken"):
            if k in meta:
                named.append("%s=%s" % (k, s(meta[k])))
    for k in ("eidValue", "eid"):
        if k in resp:
            named.append("%s=%s" % (k, s(resp[k])))
    print("binding.device\t%s" % (", ".join(named) or "no EID named in the response"))
    if named and not any(eid in n.upper() for n in named):
        finding("HIGH", "the response names an EID that is not the one supplied: the profile is bound to another device")

# 4. Notifications ride the same channel and are not signed by the SM-DP+.
if "pendingNotification" in resp or "notification" in resp:
    print("binding.notification\ta notification is being carried: its authenticity rests on the card's own signature, not on ES9")

print("findings\t%d" % len(findings))
for i, (sev, text) in enumerate(findings, 1):
    print("finding.%d\t%s\t%s" % (i, sev, text))
if findings:
    high = sum(1 for sev, _ in findings if sev == "HIGH")
    if high:
        print("verdict\ta replay or a redirected response would not be detected")
        sys.exit(1)
    if op == "unknown":
        print("verdict\tundetermined: the transaction tie is all this body can be checked for, and it is not enough to move a profile")
        sys.exit(1)
    print("verdict\tthe transaction tie is present, with warnings above")
    sys.exit(0)
print("verdict\tthe transaction and signature ties are present: a response cannot be moved to another request by this audit")
print("sent\t0")
sys.exit(0)
PY
}

# The attacks B1 names, as handoff plans: what each needs and what it proves.
sim_rsp_plan() {
    local kind="${1:-}"
    case "$kind" in
        profile-move)
            printf 'status\thandoff\n'
            printf 'what\tinstall a profile on another eUICC by replaying an ES9+ conversation\n'
            printf 'why\tthe transactionId and the SM-DP+ signature are what stop it; --rsp-audit says whether a captured exchange has both\n'
            printf 'hardware\ta test eUICC and an LPA (or an eUICC simulator) on a device you control\n'
            printf 'software\tthe ES9+ client from --es9-plus, the BPP parser from --es8-parse, and a proxy that can edit the JSON body\n'
            printf 'flow\t1. capture an initiateAuthentication exchange  2. --rsp-audit it  3. replay the response against a second request and see whether the LPA accepts it\n'
            printf 'refuses\tnothing here signs or forges an SM-DP+ signature: the audit names what is missing, it does not supply it\n' ;;
        notification-spoof)
            printf 'status\thandoff\n'
            printf 'what\tsend a HandleNotification that makes the SM-DP+ record an install that never happened\n'
            printf 'why\tthe notification is authenticated by the card, not by the LPA, so a spoofed one is a delivery question rather than a crypto one\n'
            printf 'hardware\ta test eUICC; a real SM-DP+ must be avoided\n'
            printf 'software\tthe notification builder and --es9-notification to read it back\n'
            printf 'flow\t1. build a PendingNotification with --es9-notification  2. note which fields the SM-DP+ would trust  3. send it on a test SM-DP+ and read the record\n'
            printf 'refuses\tthe card-side signature is not forged here\n' ;;
        smdp-redirect)
            printf 'status\thandoff\n'
            printf 'what\tpoint an LPA at another SM-DP+ during activation\n'
            printf 'why\tthe activation code names the SM-DP+; TLS and the SM-DP+ certificate are what stop a redirect, and --rsp-audit flags a response with no serverCertificate\n'
            printf 'hardware\ta device with a test eUICC and a proxy between LPA and SM-DP+\n'
            printf 'software\t--es9-plus to build the requests, --es9-response to parse what comes back\n'
            printf 'flow\t1. capture the activation code  2. rewrite the SM-DP+ host in the proxied request  3. --rsp-audit the response: a redirectable exchange is one with no signature tie\n'
            printf 'refuses\tno certificate is forged and no TLS is broken here\n' ;;
        *)
            printf 'ERROR\tusage: --rsp-plan <profile-move|notification-spoof|smdp-redirect>\n' >&2
            return 2 ;;
    esac
}

sim_cmd_es9_notification() {
    local json="${1:-}"
    shift 2>/dev/null || true
    while (( $# )); do
        case "$1" in
            --help|-h) sim_es9_notification_usage; return 2 ;;
            *) printf 'ERROR\tunsupported flag %s for --es9-notification\n' "$(sim_sanitize "$1")" >&2
               return 2 ;;
        esac
    done
    if [[ -z "$json" ]]; then
        sim_es9_notification_usage
        return 2
    fi
    if [[ "$json" == @* ]]; then
        local f="${json#@}"
        [[ -f "$f" ]] || { printf 'ERROR\tno such file: %s\n' "$f" >&2; return 1; }
        json=$(cat "$f") || return 1
    fi
    local hex
    hex=$(printf '%s' "$json" | python3 -c '
import base64, binascii, json, sys
raw = sys.stdin.read()
def die(msg, rc=1):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(rc)
if not raw.strip():
    die("no JSON given", 2)
try:
    body = json.loads(raw)
except Exception as e:
    die("the <JSON body> is not JSON: %s" % e)
if not isinstance(body, dict):
    die("the <JSON body> of HandleNotification is a JSON object")
if "pendingNotification" not in body:
    die("no pendingNotification key: 6.5.2.9 requires [pendingNotification], so this is not a HandleNotification request")
v = body["pendingNotification"]
if not isinstance(v, str):
    die("pendingNotification is not a base64 string (6.5.2.9 format: base64)")
try:
    b = base64.b64decode(v, validate=True)
except (binascii.Error, ValueError):
    die("pendingNotification is not valid base64")
extra = [k for k in body if k != "pendingNotification"]
if extra:
    sys.stderr.write("note\tkeys beyond pendingNotification are not in the 6.5.2.9 schema: %s\n" % ", ".join(extra))
sys.stdout.write(b.hex().upper())
') || return 1
    printf 'op\tES9+.HandleNotification\n'
    printf 'spec\tSGP.22 v2.2.2 6.5.2.9 (request schema), 5.6.4 (procedure), 5.7.10 (PendingNotification)\n'
    printf 'mep\tHTTP POST https://<smds>/gsma/rsp2/es9plus/handleNotification\n'
    printf 'expects\t204 No Content with an empty body (6.2: the POST response body SHALL be empty; 6.3: 204 for a normal notification); 6.5.2.9 defines no JSON response body\n'
    printf 'field\tpendingNotification\tbase64 -> %d octets\t6.5.2.9 required [pendingNotification]; the octets are the PendingNotification of 5.7.10\n' "$(( ${#hex} / 2 ))"
    printf 'sent\t0\n'
    sim_es8_walk "$hex" pending
}

# ── selftest — no reader, no root, no network ───────────────────────────
sim_selftest() {
    local bad=0 n_checks=0
    chk() {
        local n="$1" got="$2" want="$3"
        n_checks=$((n_checks + 1))
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export SIM_DIR="$d/loot/sim"
    export SIM_APDU_LOG="$SIM_DIR/apdus.tsv"
    export SIM_PLAN_DIR="$SIM_DIR/plans"
    mkdir -p "$SIM_DIR" "$SIM_PLAN_DIR"

    # ── 1. APDU construction, byte-exact ────────────────────────────────
    # SELECT MF 3F00: A0 A4 00 00 02 3F 00  (Case 3S, Lc=02)
    out=$(sim_build_apdu A0 A4 00 00 3F00)
    chk build-select-hex  "$(fld "$out" apdu_hex)" "A0A40000023F00"
    chk build-select-case "$(fld "$out" case)"     "3S"
    chk build-select-lc   "$(fld "$out" lc)"       "2"
    chk build-select-len  "$(fld "$out" length)"   "7"

    # SELECT by path to EF_IMSI: A0 A4 08 00 06 3F00 7FFF 6F07
    out=$(sim_apdu_select_path "3F00/7FFF/6F07")
    chk build-path-hex "$(fld "$out" apdu_hex)" "A0A40800063F007FFF6F07"
    chk build-path-lc  "$(fld "$out" lc)"       "6"

    # READ BINARY offset 0 length 10: A0 B0 00 00 0A   (Case 2S, Le=10)
    out=$(sim_apdu_read_binary 0 10)
    chk build-readbin-hex  "$(fld "$out" apdu_hex)" "A0B000000A"
    chk build-readbin-case "$(fld "$out" case)"     "2S"
    chk build-readbin-le   "$(fld "$out" le)"       "10"
    # READ BINARY at a non-zero offset: offset 0x0102 = 258.
    out=$(sim_apdu_read_binary 258 16)
    chk build-readbin-off  "$(fld "$out" apdu_hex)" "A0B0010210"

    # READ RECORD 1 absolute, Le=256 -> Le byte 0x00.
    out=$(sim_apdu_read_record 1 04 256)
    chk build-readrec-hex  "$(fld "$out" apdu_hex)" "A0B2010400"
    chk build-readrec-case "$(fld "$out" case)"     "2S"
    chk build-readrec-le   "$(fld "$out" le)"       "256"
    out=$(sim_apdu_read_record 3 04 40)
    chk build-readrec-rec3 "$(fld "$out" apdu_hex)" "A0B2030428"
    # Mode 02 = "next record" (P2 bit assignment from ISO 7816-4 §7.2.1).
    out=$(sim_apdu_read_record 2 02 40)
    chk build-readrec-next "$(fld "$out" apdu_hex)" "A0B2020228"

    # GET RESPONSE for 16 bytes: A0 C0 00 00 10
    out=$(sim_apdu_get_response 16)
    chk build-getresp "$(fld "$out" apdu_hex)" "A0C0000010"

    # Case 4S: SELECT with data AND Le stays short.
    out=$(sim_build_apdu A0 A4 00 00 3F00 00)
    chk build-case4-hex  "$(fld "$out" apdu_hex)" "A0A40000023F0000"
    chk build-case4-case "$(fld "$out" case)"     "4S"
    chk build-case4-le   "$(fld "$out" le)"       "256"

    # Case 1: header only.
    out=$(sim_build_apdu 00 00 00 00)
    chk build-case1-hex  "$(fld "$out" apdu_hex)" "00000000"
    chk build-case1-case "$(fld "$out" case)"     "1"
    chk build-case1-lc   "$(fld "$out" lc)"       "0"

    # Extended APDU: a 300-byte body forces Lc as 00 || 012C.
    local big=""; local i
    for (( i = 0; i < 300; i++ )); do big+="AA"; done
    out=$(sim_build_apdu 80 E2 01 00 "$big")
    chk build-ext-case   "$(fld "$out" case)"     "3E"
    chk build-ext-lc     "$(fld "$out" lc)"       "300"
    chk build-ext-ext    "$(fld "$out" extended)" "yes"
    chk build-ext-prefix "$(printf '%s' "$(fld "$out" apdu_hex)" | cut -c1-14)" "80E2010000012C"
    chk build-ext-len    "$(fld "$out" length)"   "307"
    # A short Le written as 4 hex digits selects the extended form.
    # Le given as four hex digits selects the extended form: 00 || 0000.
    out=$(sim_build_apdu A0 B0 00 00 "" 0000)
    chk build-ext-le     "$(fld "$out" apdu_hex)" "A0B00000000000"
    chk build-ext-le-val "$(fld "$out" le)"       "65536"
    chk build-ext-le-len "$(fld "$out" length)"   "7"
    chk build-ext-le-case "$(fld "$out" case)"    "2E"

    # Argument validation must be non-zero, never a silent success.
    chk build-bad-cla   "$(sim_build_apdu ZZ A4 00 00 >/dev/null 2>&1; echo $?)" "2"
    chk build-bad-p1    "$(sim_build_apdu A0 A4 XYZ 00 >/dev/null 2>&1; echo $?)" "2"
    chk build-bad-data  "$(sim_build_apdu A0 A4 00 00 ABC >/dev/null 2>&1; echo $?)" "2"
    chk build-bad-le    "$(sim_build_apdu A0 A4 00 00 '' FFFFF >/dev/null 2>&1; echo $?)" "2"
    chk select-bad-fid  "$(sim_apdu_select_fid 123 >/dev/null 2>&1; echo $?)" "2"
    chk select-bad-path "$(sim_apdu_select_path 3F0 >/dev/null 2>&1; echo $?)" "2"
    chk readbin-off-rng "$(sim_apdu_read_binary 40000 10 >/dev/null 2>&1; echo $?)" "1"
    chk readbin-le-zero "$(sim_apdu_read_binary 0 0 >/dev/null 2>&1; echo $?)" "1"
    chk readrec-bad-num "$(sim_apdu_read_record 0 04 10 >/dev/null 2>&1; echo $?)" "1"
    chk readrec-overflow "$(sim_apdu_read_record 255 04 10 >/dev/null 2>&1; echo $?)" "1"
    chk readrec-bad-mode "$(sim_apdu_read_record 1 ZZ 10 >/dev/null 2>&1; echo $?)" "2"
    chk getresp-zero    "$(sim_apdu_get_response 0 >/dev/null 2>&1; echo $?)" "1"

    # ── 2. Command APDU parsing, round-trip against the builder ─────────
    out=$(sim_parse_capdu "A0A40000023F00")
    chk parse-capdu-case "$(fld "$out" case)" "3S"
    chk parse-capdu-cla  "$(fld "$out" cla)"  "A0"
    chk parse-capdu-ins  "$(fld "$out" ins)"  "A4"
    chk parse-capdu-p1   "$(fld "$out" p1)"   "00"
    chk parse-capdu-lc   "$(fld "$out" lc)"   "2"
    chk parse-capdu-data "$(fld "$out" data)" "3F00"
    chk parse-capdu-short-rc      "$(sim_parse_capdu "A0A4" >/dev/null 2>&1; echo $?)" "1"
    chk parse-capdu-len-mismatch  "$(sim_parse_capdu "A0A40000023F" >/dev/null 2>&1; echo $?)" "1"
    chk parse-capdu-not-hex       "$(sim_parse_capdu "A0A4ZZ" >/dev/null 2>&1; echo $?)" "2"

    out=$(sim_parse_capdu "00B000000A")
    chk parse-capdu-2s    "$(fld "$out" case)" "2S"
    chk parse-capdu-2s-le "$(fld "$out" le)"   "10"

    # Extended round-trip: build a 300-byte Case 3E and parse it back.
    local built; built=$(fld "$(sim_build_apdu 80 E2 01 00 "$big")" apdu_hex)
    out=$(sim_parse_capdu "$built")
    chk rt-ext-case     "$(fld "$out" case)"     "3E"
    chk rt-ext-lc       "$(fld "$out" lc)"       "300"
    chk rt-ext-ext      "$(fld "$out" extended)" "yes"
    chk rt-ext-data-len "$(sim_hex_bytes "$(fld "$out" data)")" "300"

    # Case 4S round-trip.
    built=$(fld "$(sim_build_apdu A0 A4 00 00 3F00 00)" apdu_hex)
    out=$(sim_parse_capdu "$built")
    chk rt-4s-case "$(fld "$out" case)" "4S"
    chk rt-4s-le   "$(fld "$out" le)"   "256"
    chk rt-4s-data "$(fld "$out" data)" "3F00"

    # Case 2S round-trip for READ RECORD.
    built=$(fld "$(sim_apdu_read_record 1 04 256)" apdu_hex)
    out=$(sim_parse_capdu "$built")
    chk rt-2s-case "$(fld "$out" case)" "2S"
    chk rt-2s-p1   "$(fld "$out" p1)"   "01"
    chk rt-2s-p2   "$(fld "$out" p2)"   "04"
    chk rt-2s-le   "$(fld "$out" le)"   "256"

    # ── 3. Response APDU and status-word classification ─────────────────
    out=$(sim_parse_rapdu "9000")
    chk rapdu-sw      "$(fld "$out" sw)"        "9000"
    chk rapdu-status  "$(fld "$out" status)"    "success"
    chk rapdu-datalen "$(fld "$out" data_len)"  "0"

    out=$(sim_parse_rapdu "9802112233449000")
    chk rapdu-data     "$(fld "$out" data)"     "980211223344"
    chk rapdu-data-len "$(fld "$out" data_len)" "6"
    chk rapdu-sw2      "$(fld "$out" sw2)"      "00"

    chk sw-success   "$(sim_sw_label 9000)" "success"
    chk sw-6a82      "$(sim_sw_label 6A82)" "error: file or application not found"
    chk sw-6982      "$(sim_sw_label 6982)" "error: security status not satisfied (PIN or key required)"
    chk sw-6983      "$(sim_sw_label 6983)" "error: authentication method blocked (PIN/PUK/ADM locked)"
    chk sw-6a83      "$(sim_sw_label 6A83)" "error: record not found"
    chk sw-6a86      "$(sim_sw_label 6A86)" "error: incorrect P1-P2 parameters"
    chk sw-6d00      "$(sim_sw_label 6D00)" "error: instruction code not supported or invalid"
    chk sw-6700      "$(sim_sw_label 6700)" "error: wrong length (Lc inconsistent with P1/P2)"
    chk sw-6c1c      "$(sim_sw_label 6C1C)" "error: wrong Le, retry with Le=1C"
    chk sw-6c1c-len  "$(sim_sw_len 6C1C)"   "28"
    chk sw-6110      "$(sim_sw_label 6110)" "success:10 bytes available (GET RESPONSE)"
    chk sw-6110-len  "$(sim_sw_len 6110)"   "16"
    chk sw-9000-len  "$(sim_sw_len 9000)"   "-"
    chk sw-63c3      "$(sim_sw_label 63C3)" "warning: counter is C3 — PIN blocked after counter 0"
    chk sw-unknown   "$(sim_sw_label 6F99)" "error: SW1=6F, no precise diagnosis"
    # A status word the table has never seen must say so, not guess.
    chk sw-never-seen "$(sim_sw_label 1A2B)" "unknown"
    chk sw-bad-input  "$(sim_sw_label ZZ)"   "unknown"
    chk sw-bad-rc     "$(sim_sw_label ZZ >/dev/null 2>&1; echo $?)" "1"
    chk sw-ok-9000    "$(sim_sw_ok 9000; echo $?)" "0"
    chk sw-ok-61xx    "$(sim_sw_ok 6110; echo $?)" "0"
    chk sw-not-6a82   "$(sim_sw_ok 6A82; echo $?)" "1"
    chk sw-not-6c1c   "$(sim_sw_ok 6C1C; echo $?)" "1"
    chk rapdu-short-rc "$(sim_parse_rapdu "90" >/dev/null 2>&1; echo $?)" "1"

    # ── 4. USIM file table ──────────────────────────────────────────────
    chk file-mf     "$(sim_file_name 3F00 | cut -d'|' -f1)" "MF (master file)"
    chk file-dfgsm  "$(sim_file_name 7F20 | cut -d'|' -f1)" "DF_GSM"
    chk file-iccid  "$(sim_file_name 2FE2 | cut -d'|' -f1)" "EF_ICCID"
    chk file-imsi   "$(sim_file_name 6F07 | cut -d'|' -f1)" "EF_IMSI"
    chk file-kc     "$(sim_file_name 6F20 | cut -d'|' -f1)" "EF_Kc (GSM ciphering key)"
    chk file-ad     "$(sim_file_name 6FAD | cut -d'|' -f1)" "EF_AD (Administrative Data)"
    chk file-loci   "$(sim_file_name 6F7E | cut -d'|' -f1)" "EF_LOCI (Location Information)"
    chk file-keys   "$(sim_file_name 6F08 | cut -d'|' -f1)" "EF_KEYS (Ciphering and Integrity Keys)"
    chk file-spn    "$(sim_file_name 6F46 | cut -d'|' -f1)" "EF_SPN (Service Provider Name)"
    chk file-adf    "$(sim_file_name 7FFF | cut -d'|' -f1)" "ADF_USIM"
    chk file-lower  "$(sim_file_name 6f07 | cut -d'|' -f1)" "EF_IMSI"
    chk file-path   "$(sim_file_path 6F07)" "3F00/7FFF/6F07"
    chk file-path-g "$(sim_file_path 2FE2)" "3F00/7F20/2FE2"
    chk file-unknown "$(sim_file_name 1234 | cut -d'|' -f1)" "unknown EF/DF"

    # ── 5. ICCID decode: ten octets of plain BCD, nothing to skip ───────
    # pySim's encoder turns the ICCID 8986000000000000002 into
    # 98 68 00 00 00 00 00 00 00 f2, so the leading 0x98 is the digits 8 and
    # 9. Read as a "marker octet" it shortened the ICCID by two digits and
    # made every field after it wrong -- country, issuer, check digit.
    out=$(sim_decode_iccid "986800000000000000f2")
    chk iccid-digits   "$(fld "$out" iccid)"        "8986000000000000002"
    chk iccid-length   "$(fld "$out" length)"       "19"
    chk iccid-issuer   "$(fld "$out" issuer)"       "89"
    chk iccid-cc       "$(fld "$out" calling_code)" "86"
    chk iccid-country  "$(fld "$out" country)"      "China"
    chk iccid-filler   "$(fld "$out" filler)"       "yes"
    chk iccid-check    "$(fld "$out" check_digit)"  "2"
    chk iccid-luhn     "$(fld "$out" luhn)"         "valid"
    # Twenty digits and no filler: a UK issuer, country calling code 44.
    out=$(sim_decode_iccid "984405214365870921f4")
    chk iccid-2-digits "$(fld "$out" iccid)"        "8944501234567890124"
    chk iccid-2-cc     "$(fld "$out" calling_code)" "44"
    chk iccid-2-country "$(fld "$out" country)"     "United Kingdom"
    chk iccid-2-luhn   "$(fld "$out" luhn)"         "valid"
    # A check digit that does not add up is reported, not rounded away.
    out=$(sim_decode_iccid "98680000000000000012")
    chk iccid-badluhn  "$(fld "$out" luhn)"         "INVALID"
    chk iccid-badcheck "$(fld "$out" check_digit)"  "1"
    chk iccid-bad-hex   "$(sim_decode_iccid ZZZZ >/dev/null 2>&1; echo $?)" "2"
    chk iccid-too-short "$(sim_decode_iccid "98" >/dev/null 2>&1; echo $?)" "1"

    # ── 6. IMSI decode: the length byte, then the parity nibble ─────────
    # EF_IMSI for 310260123456789 is 08 39 01 62 10 32 54 76 98. The 39 is
    # the parity 9 (odd digit count) in the low nibble and the first digit 3
    # in the high one, so the nibble swap leaves the parity as the leading
    # character "9" -- read as a digit it made the IMSI 9310260123456789 and
    # put the card in MCC 931 (unknown) instead of 310 (United States).
    out=$(sim_decode_imsi "083901621032547698")
    chk imsi-digits    "$(fld "$out" imsi)"          "310260123456789"
    chk imsi-length    "$(fld "$out" length)"        "15"
    chk imsi-lenbyte   "$(fld "$out" length_byte)"   "8"
    chk imsi-bodybytes "$(fld "$out" body_bytes)"    "8"
    chk imsi-lagree    "$(fld "$out" length_agrees)" "yes"
    chk imsi-parity    "$(fld "$out" parity)"        "odd"
    chk imsi-pagree    "$(fld "$out" parity_agrees)" "yes"
    chk imsi-mcc       "$(fld "$out" mcc)"           "310"
    chk imsi-mnc2      "$(fld "$out" mnc_2digit)"    "26"
    chk imsi-mnc3      "$(fld "$out" mnc_3digit)"    "260"
    chk imsi-hplmn2    "$(fld "$out" hplmn_2digit)"  "310-26"
    chk imsi-hplmn3    "$(fld "$out" hplmn_3digit)"  "310-260"
    chk imsi-country   "$(fld "$out" country)"       "United States"
    chk imsi-msin      "$(fld "$out" msin)"          "0123456789"

    # Fourteen digits, an even count: parity 1, and the odd number of nibbles
    # leaves the filler F at the end -- 08 31 01 62 10 32 54 76 f8.
    out=$(sim_decode_imsi "0831016210325476f8")
    chk imsi-even-digits "$(fld "$out" imsi)"   "31026012345678"
    chk imsi-even-length "$(fld "$out" length)" "14"
    chk imsi-even-parity "$(fld "$out" parity)" "even"
    chk imsi-even-filler "$(fld "$out" filler)" "F"

    # An encoder that pads past its own length byte: the discrepancy is
    # reported and the digits still read. 07 29 26 10 21 43 65 87 ff is how
    # pySim writes the thirteen-digit 2620112345678.
    out=$(sim_decode_imsi "0729261021436587ff")
    chk imsi-padded-digits   "$(fld "$out" imsi)"          "2620112345678"
    chk imsi-padded-disagree "$(fld "$out" length_agrees)" "no"
    chk imsi-padded-filler   "$(fld "$out" filler)"        "F"

    # A bare body with no length byte in front of it still decodes.
    out=$(sim_decode_imsi "3901621032547698")
    chk imsi-nolen-digits "$(fld "$out" imsi)"        "310260123456789"
    chk imsi-nolen-lenb   "$(fld "$out" length_byte)" "none"

    # A body whose leading nibble is neither 1 nor 9 is not an EF_IMSI, and
    # saying so beats decoding a parity nibble as a digit.
    chk imsi-no-parity "$(sim_decode_imsi "13200621436587F9" >/dev/null 2>&1; echo $?)" "1"
    chk imsi-bad-hex   "$(sim_decode_imsi "ZZ" >/dev/null 2>&1; echo $?)" "2"
    chk imsi-too-short "$(sim_decode_imsi "0813" >/dev/null 2>&1; echo $?)" "1"

    # ── 7. EF_AD administrative data (TS 31.102 §4.2.18) ────────────────
    # byte1='00' normal operation, bytes2-3 = manufacturer specific,
    # byte4='02' -> MNC length 2.
    out=$(sim_parse_ef_ad "00000002")
    chk ad-mode     "$(fld "$out" mode)"              "normal operation"
    chk ad-modecode "$(fld "$out" mode_code)"         "0"
    chk ad-specific "$(fld "$out" specific_facilities)" "no"
    chk ad-mnclen   "$(fld "$out" mnc_length)"        "2"
    chk ad-b1       "$(fld "$out" byte1)"             "00"
    # byte1='01' -> normal operation + specific facilities, so byte 3 bits
    # are live: b1 ciphering indicator, b2 CSG display, b3 ProSe PS, b4 eDRX.
    # byte1='01' = normal operation + specific facilities -> byte 3 bits are
    # live. byte3='0F' = b1..b4 all set: ciphering indicator, CSG list only,
    # ProSe Public Safety, eDRX. byte4='03' -> MNC length 3.
    out=$(sim_parse_ef_ad "01000F03")
    chk ad-spec-mode "$(fld "$out" mode)"  "normal operation + specific facilities"
    chk ad-specific2 "$(fld "$out" specific_facilities)" "yes"
    chk ad-cipher    "$(fld "$out" b3_ciphering_indicator)" "enabled (ciphering indicator shown to the user)"
    chk ad-csg       "$(fld "$out" b3_csg_display)" "operator CSG list only"
    chk ad-prose     "$(fld "$out" b3_prose_public_safety)" "authorised for ProSe Public Safety without the ProSe Function"
    chk ad-edrx      "$(fld "$out" b3_extended_drx)" "ME may modify the UICC polling interval / disable the interface in eDRX"
    chk ad-mnclen3   "$(fld "$out" mnc_length)" "3"
    # byte1='80' -> type approval; byte1='04' -> cell test operation.
    chk ad-mode-ta   "$(sim_parse_ef_ad 80000002 | awk -F'\t' '$1=="mode"{print $2}')" "type approval operations"
    chk ad-mode-cell "$(sim_parse_ef_ad 04000003 | awk -F'\t' '$1=="mode"{print $2}')" "cell test operation"
    chk ad-mode-rfu  "$(sim_parse_ef_ad 0A000003 | awk -F'\t' '$1=="mode"{print $2}')" "RFU (reserved for future use)"
    chk ad-mnc-reserved "$(sim_parse_ef_ad 00000007 | awk -F'\t' '$1=="mnc_length"{print $2}')" "7 (reserved — only 2 and 3 are specified)"
    chk ad-rfu-bytes "$(fld "$(sim_parse_ef_ad 0000000200)" rfu_bytes)" "1"
    chk ad-bad-hex   "$(sim_parse_ef_ad "XY" >/dev/null 2>&1; echo $?)" "2"
    chk ad-too-short "$(sim_parse_ef_ad "0000" >/dev/null 2>&1; echo $?)" "1"

    # ── 8. OTA TPDU parse: TAR, SPI, KIc/KID, counter ───────────────────
    # SMS-DELIVER, UDHI=1, OA = +12345678901, PID 40, DCS F6.
    # TP-UD = 05 70 14 <20-octet TS 23.048 Command Packet>
    #   CPI 01, CPL 14 (=20: CHI..end of secured data), CHI 01, CHL 0E (=14:
    #   SPI..end of RC/CC/DS -> no RC/CC/DS), SPI 1742, KIc 01, KID 01,
    #   TAR B00002, CNTR 0000000001, PCNTR 00, then 2 octets of secured data.
    local ota="44"
    ota+="0B"                       # OA length: 11 digits
    ota+="91"                       # TON=international
    ota+="2143658709F1"             # +12345678901 nibble-swapped
    ota+="40"                       # PID
    ota+="F6"                       # DCS: 8-bit, class 2
    ota+="41202132547698"           # SCTS
    ota+="14"                       # UDL = 20 octets of TP-UD
    ota+="057011"                   # UDHL 05, IEI 70, IEDL 11 (17 bytes)
    ota+="01"                       # CPI  = 01 Command Packet
    ota+="11"                       # CPL  = 17 (= packet len 19 - CPI/CPL 2)
    ota+="01"                       # CHI  = 01 Command Header
    ota+="0E"                       # CHL  = 14 (SPI..end of RC/CC/DS)
    ota+="1742"                     # SPI  = 0x1742
    ota+="01"                       # KIc  = 01
    ota+="01"                       # KID  = 01
    ota+="B00002"                   # TAR  = SIM Data Download
    ota+="0000000001"               # CNTR = 1
    ota+="00"                       # PCNTR = 0
    ota+="AABB"                     # 2 octets of secured data

    out=$(sim_parse_ota "$ota")
    chk ota-mti      "$(fld "$out" mti)"        "SMS-DELIVER"
    chk ota-udhi     "$(fld "$out" udhi)"       "1"
    chk ota-oa       "$(fld "$out" oa)"         "international +12345678901"
    chk ota-pid      "$(fld "$out" pid)"        "40"
    chk ota-valid    "$(fld "$out" ota_valid)"  "yes"
    chk ota-udhl     "$(fld "$out" udhl)"       "5"
    chk ota-cpi      "$(fld "$out" cpi)"        "01"
    chk ota-cpi-txt  "$(fld "$out" cpi_meaning)" "Command Packet (CPI=01)"
    chk ota-cpl      "$(fld "$out" cpl)"        "17"
    chk ota-chi      "$(fld "$out" chi)"        "01"
    chk ota-chl      "$(fld "$out" chl)"        "14"
    chk ota-spi      "$(fld "$out" spi)"        "5954"
    # CHL 14 with the 13-octet prefix leaves exactly one octet of RC/CC/DS,
    # which is why the arm says 1 and the parse prints its rccds_note.
    chk ota-rccds-len "$(fld "$out" rccds_len)" "1"
    chk ota-rccds-note "$(fld "$out" rccds_note | grep -c 'does not follow')" "1"
    # ── the TS 31.115 SMS packet layout (no CHI, two-octet CPL) ──────────
    # The IE is the packet pySim builds for SPI 1600 (counter 2, ciphering, CC),
    # TAR b00001, wrapped in an SMS-DELIVER with UDHI and IEI 70 so that the
    # end-to-end path is what is under test and not a helper called directly.
    local smstpdu="40039121F30004240101000000002524702200201516001515b000018405f7d95d3f0f438ae0669d9f5c2bd3ee323f8f0f19105a"
    local sout; sout=$(sim_parse_ota "$smstpdu")
    chk sms-ota-valid   "$(fld "$sout" ota_valid)" "yes"
    chk sms-ota-dialect "$(fld "$sout" dialect)" "ts31.115-sms-packet"
    chk sms-ota-cpl     "$(fld "$sout" cpl)" "32"
    chk sms-ota-chl     "$(fld "$sout" chl)" "21"
    chk sms-ota-cpl-oct "$(fld "$sout" cpl_len_octets)" "2"
    chk sms-ota-chl-oct "$(fld "$sout" chl_len_octets)" "1"
    chk sms-ota-spi     "$(fld "$sout" spi_hex)" "1600"
    chk sms-ota-rccds   "$(fld "$sout" spi_b2b1_rccds)" "2"
    chk sms-ota-cipher  "$(fld "$sout" spi_b3_ciphering)" "1"
    chk sms-ota-cc-len  "$(fld "$sout" cc_bytes)" "8"
    chk sms-ota-tar     "$(fld "$sout" tar)" "B00001"
    chk sms-ota-kic     "$(fld "$sout" kic)" "15"
    chk sms-ota-nocpi   "$(fld "$sout" cpi)" "-"
    chk sms-ota-secured "$(fld "$sout" secured | cut -d' ' -f1)" "yes"
    # The payload is ciphered, so the verb says so instead of printing the
    # ciphertext as though it were a command.
    chk sms-ota-note    "$(fld "$sout" secured_note | grep -c 'does not decrypt')" "1"
    chk sms-ota-noapdu  "$(fld "$sout" apdu)" ""
    # A CPL that does not describe the packet must be refused.
    chk sms-ota-badcpl  "$(sim_parse_ota "${smstpdu:0:44}FF${smstpdu:48}" >/dev/null 2>&1; echo $?)" "1"
    # The CAT_TP fixture still reports its own dialect, so the discriminator
    # cannot quietly swallow one layout into the other.
    chk cat-ota-dialect "$(fld "$out" dialect)" "ts102.225-cat-tp"
    # With CHL 14 the RC/CC/DS field is a single octet, so only the trailing
    # BB remains as secured data. The old reading (CHL-14) took AABB, i.e. it
    # swallowed the CC's only octet into the payload.
    chk ota-secured  "$(fld "$out" secured_data)" "BB"
    chk ota-cpl-check "$(fld "$out" cpl_check)" "consistent"
    chk ota-kic-hex  "$(fld "$out" cipher_hex)"   "0x01"
    chk ota-kid-hex  "$(fld "$out" integrity_hex)" "0x01"
    chk ota-tar      "$(fld "$out" tar)"        "B00002"
    chk ota-tar-name "$(fld "$out" tar_known)"  "SIM Data Download (TS 23.048 §5.1)"
    chk ota-cntr     "$(fld "$out" cntr)"       "1"
    chk ota-pcntr    "$(fld "$out" pcntr)"      "00"
    chk ota-replay   "$(fld "$out" replay_note)" "SPI b5b4=10 — the RE accepts if CNTR > its stored value (tolerant, allows gaps)"

    # SPI 0x1742 = octet 1 0x17 (0001 0111) and octet 2 0x42 (0100 0010):
    #   octet 1: b8..b6=000 reserved, b5b4=10 (process iff CNTR > RE value),
    #            b3=1 ciphering applied, b2b1=11 digital signature
    #   octet 2: b8b7=01 reserved bits set, b6=0 PoR via SMS-DELIVER-REPORT,
    #            b5=0 PoR not ciphered, b4b3=00 no RC on the PoR,
    #            b2b1=10 PoR only when an error has occurred
    out=$(sim_spi_decode 5954)
    chk spi-octet1   "$(fld "$out" spi_octet1)" "17"
    chk spi-octet2   "$(fld "$out" spi_octet2)" "42"
    chk spi-rccds    "$(fld "$out" spi_rccds)"  "Digital Signature (DS)"
    chk spi-b2b1     "$(fld "$out" spi_b2b1_rccds)" "3"
    chk spi-b3       "$(fld "$out" spi_b3_ciphering)" "1"
    chk spi-b5b4     "$(fld "$out" spi_b5b4_counter)" "2"
    chk spi-ciphering "$(fld "$out" spi_ciphering)" "applied"
    chk spi-counter  "$(fld "$out" spi_counter)" "process iff counter value is higher than the value in the RE"
    chk spi-por      "$(fld "$out" spi_por)"     "PoR required only when an error has occurred"
    chk spi-por-trans "$(fld "$out" spi_por_transport)" "SMS-DELIVER-REPORT"
    chk spi-clean    "$(fld "$out" spi_weakness | cut -c1-4)" "none"

    # SPI 0x0000: nothing applied at all — the critical case.
    out=$(sim_spi_decode 0)
    chk spi-zero-cipher  "$(fld "$out" spi_ciphering)" "NOT applied (payload in the clear)"
    chk spi-zero-counter "$(fld "$out" spi_counter)" "no counter available (field present but ignored by the RE)"
    chk spi-zero-weak    "$(fld "$out" spi_weakness | grep -c 'NOT ciphered')" "1"
    chk spi-zero-weak2   "$(fld "$out" spi_weakness | grep -c 'no anti-replay counter is applied')" "1"
    chk spi-zero-weak3   "$(fld "$out" spi_weakness | grep -c 'no integrity protection at all')" "1"

    # Counter sub-field (b5b4), built from explicit octets:
    #   0x18 = 0001 1000 -> b8b7=00, b6=0, b5b4=11 (strict RE+1)
    #   0x00 = 0000 0000 -> b5b4=00 (no counter)
    #   0x08 = 0000 1000 -> b5b4=01 (informational only)
    chk spi-b5b4-3 "$(fld "$(sim_spi_decode $(( 0x1800 )))" spi_counter)" "process iff counter value is exactly RE+1 (strict)"
    chk spi-b5b4-0 "$(fld "$(sim_spi_decode $(( 0x0000 )))" spi_counter)" "no counter available (field present but ignored by the RE)"
    chk spi-b5b4-1 "$(fld "$(sim_spi_decode $(( 0x0800 )))" spi_counter)" "counter available, NO replay or sequence checking"
    # A packet with ciphering (b3=1), an enforced counter (b5b4=11) and an
    # integrity field (b2b1=01 RC) reports "none" rather than a warning.
    # octet1 0x1D = 0001 1101 -> b5b4=11 strict, b3=1 ciphering, b2b1=01 RC.
    out=$(sim_spi_decode $(( 0x1D00 )))
    chk spi-all-good "$(fld "$out" spi_weakness | cut -c1-4)" "none"
    chk spi-all-good-rccds "$(fld "$out" spi_rccds)" "Redundancy Check (RC)"
    chk spi-all-good-cipher "$(fld "$out" spi_ciphering)" "applied"

    chk spi-bad-range  "$(sim_spi_decode 70000 >/dev/null 2>&1; echo $?)" "2"
    chk spi-bad-nonnum "$(sim_spi_decode abc >/dev/null 2>&1; echo $?)" "2"

    # KIc/KID strength. TS 102 225 §5.1.2 puts the KEY SET in b8..b5, the
    # mode in b4b3 and the algorithm family in b2b1, so 0x41 is key set 4
    # DES-CBC while 0x15 is key set 1 2-key 3DES -- the low nibble 5 is what
    # names 3DES, it is not a key set number.
    chk kic-des-cbc  "$(fld "$(sim_kic_kid_meaning 41 cipher)" cipher_strength | cut -c1-4)" "weak"
    chk kic-des-mode "$(fld "$(sim_kic_kid_meaning 41 cipher)" cipher_mode)" "0"
    chk kic-des-meaning "$(fld "$(sim_kic_kid_meaning 41 cipher)" cipher_mode_meaning)" "DES in CBC mode (56-bit key, zero IV)"
    chk kic-3des2    "$(fld "$(sim_kic_kid_meaning 15 cipher)" cipher_mode)" "1"
    chk kic-3des3    "$(fld "$(sim_kic_kid_meaning 19 cipher)" cipher_strength | cut -c1-10)" "acceptable"
    chk kic-ecb      "$(fld "$(sim_kic_kid_meaning 4D cipher)" cipher_strength | cut -c1-8)" "critical"
    chk kic-keyset   "$(fld "$(sim_kic_kid_meaning 4D cipher)" cipher_key_set)" "4"
    chk kic-implicit "$(fld "$(sim_kic_kid_meaning 40 cipher)" cipher_algorithm)" "algorithm known implicitly by both entities"
    chk kic-propriet "$(fld "$(sim_kic_kid_meaning C3 cipher)" cipher_strength | cut -c1-7)" "unknown"
    chk kic-bad      "$(sim_kic_kid_meaning ZZ >/dev/null 2>&1; echo $?)" "2"
    chk ota-key-pair "$(sim_cmd_ota_key 15 25 | awk -F'\t' '$1=="finding"{print $2}' | head -1)" "MEDIUM"
    chk ota-key-same "$(sim_cmd_ota_key 15 15 | grep -c 'same key set 1')" "1"

    # OTA key weakness findings.
    chk key-weak-zero    "$(sim_ota_key_weakness 00 00 | grep -c 'O1: mechanism not applied')" "1"
    chk key-weak-same    "$(sim_ota_key_weakness 41 41 | grep -c 'O8: KIc == KID')" "1"
    # 0x41 and 0x45 share the KEY SET (the high nibble, 4) and differ in the
    # mode bits, so KIc != KID while the same provisioned key is reused.
    chk key-weak-sameset "$(sim_ota_key_weakness 41 45 | grep -c 'O9: KIc and KID reference key set 4')" "1"
    chk key-weak-des     "$(sim_ota_key_weakness 41 45 | grep -c 'single DES-CBC')" "1"
    chk key-weak-ecb     "$(sim_ota_key_weakness 4D 45 | grep -c 'DES-ECB')" "1"
    chk key-weak-2des3   "$(sim_ota_key_weakness 55 51 | grep -c '2-key 3DES')" "1"
    chk key-weak-first   "$(sim_ota_key_weakness 15 25 | grep -c 'O10: key set 1')" "1"
    chk key-weak-none    "$(sim_ota_key_weakness 62 62 | grep -c 'O8: KIc == KID')" "1"

    # Non-OTA TPDUs must fail loudly, not be misread as OTA.
    chk ota-not-udhi    "$(sim_parse_ota "040B912143658709F140F6412021325476980A" >/dev/null 2>&1; echo $?)" "1"
    chk ota-too-short   "$(sim_parse_ota "44" >/dev/null 2>&1; echo $?)" "1"
    chk ota-bad-hex     "$(sim_parse_ota "ZZZZ" >/dev/null 2>&1; echo $?)" "2"
    # A UDH whose only IE is a concatenation (0x00) is not OTA.
    chk ota-concat-only "$(sim_parse_ota "440B912143658709F140F6412021325476980C0500030102AA" >/dev/null 2>&1; echo $?)" "1"
    # UDHI set but no UDH bytes at all.
    chk ota-empty-ud    "$(sim_parse_ota "440B912143658709F140F64120213254769800" >/dev/null 2>&1; echo $?)" "1"

    # ── 9. BER-TLV length decode (TS 101 220 §5.1.1) ────────────────────
    chk berlen-short  "$(sim_ota_berlen 0 "14")" "20 1"
    chk berlen-81     "$(sim_ota_berlen 0 "8114")" "20 2"
    chk berlen-82     "$(sim_ota_berlen 0 "820114")" "276 3"
    chk berlen-indef  "$(sim_ota_berlen 0 "80" >/dev/null 2>&1; echo $?)" "1"
    chk berlen-trunc  "$(sim_ota_berlen 0 "82" >/dev/null 2>&1; echo $?)" "1"

    # ── 10. eSIM: RSP roles, profile states, metadata walker ────────────
    chk rsp-roles  "$(sim_rsp_roles | grep -c '^sm-dp+\|^lpa\|^euicc\|^isd-r\|^isd-p\|^sm-ds')" "6"
    chk rsp-smdpp  "$(sim_rsp_roles | grep -c '^sm-dp+')" "1"
    chk prof-states "$(sim_profile_state_table | tail -n +2 | grep -c .)" "3"
    chk prof-enabled "$(sim_profile_state_table | grep -c '^enabled')" "1"
    chk prof-disabled "$(sim_profile_state_table | grep -c '^disabled')" "1"
    chk prof-deleted "$(sim_profile_state_table | grep -c '^deleted')" "1"

    # ProfileMetadata: SEQUENCE { [1] OCTET STRING(len 2), [12] OCTET STRING(len 1) }
    # 30 09  A1 04 04 02 98 11  AC 01 01
    #  ^seq ^len  ^[1] ^len ^octstr ^len ^bytes ^[12] ^len ^value
    # ProfileMetadata: SEQUENCE { [1] { OCTET STRING }, [12] { INTEGER } }
    # SGP.22 context tags for TLV-typed fields are constructed (0xA1, 0xAC),
    # so the walker must descend into them.
    #   30 0B  A1 04 04 02 98 11  AC 03 02 01 01
    local meta="300BA1040402981 1AC03020101"; meta="${meta// /}"
    out=$(sim_parse_profile_metadata "$meta")
    chk meta-seq     "$(printf '%s\n' "$out" | grep -c '^field	0	30	11	SEQUENCE')" "1"
    chk meta-iccid   "$(printf '%s\n' "$out" | grep -c '^field	1	A1	4	\[1\] iccid')" "1"
    chk meta-iccid-v "$(printf '%s\n' "$out" | grep -c '^field	2	04	2	OCTET STRING')" "1"
    chk meta-state   "$(printf '%s\n' "$out" | grep -c '^field	1	AC	3	\[12\] profileState')" "1"
    chk meta-state-v "$(printf '%s\n' "$out" | grep -c '^field	2	02	1	INTEGER')" "1"
    chk meta-fields  "$(printf '%s\n' "$out" | grep -c '^field	')" "5"
    # A truncated blob must be reported, not silently accepted.
    chk meta-truncated "$(sim_parse_profile_metadata "3007A1029811" >/dev/null 2>&1; echo $?)" "1"
    # A long-form length (0x81) must be decoded as a value, not mistaken for
    # 0x81 bytes of content.
    out=$(sim_parse_profile_metadata "3081030401FF")
    chk meta-longform "$(printf '%s\n' "$out" | grep -c '^field	0	30	3	SEQUENCE')" "1"
    chk meta-longform-inner "$(printf '%s\n' "$out" | grep -c '^field	1	04	1	OCTET STRING')" "1"
    chk meta-indef    "$(sim_parse_profile_metadata "3080040000" >/dev/null 2>&1; echo $?)" "1"
    chk meta-bad      "$(sim_parse_profile_metadata "ZZ" >/dev/null 2>&1; echo $?)" "2"

    # ── 11. Plan files carry status: handoff and name the hardware ──────
    local k
    for k in ota-replay sat-wib esim-download; do
        out=$(sim_plan "$k" 2>/dev/null)
        chk "plan-$k-status" "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
        chk "plan-$k-file"   "$(printf '%s\n' "$out" | grep -c "^plan_file	")" "1"
    done
    local pf hwhits
    pf=$(find "$SIM_PLAN_DIR" -name 'plan_ota-replay_*.txt' | head -n1)
    chk plan-file-exists "$([[ -f "$pf" ]] && echo yes || echo no)" "yes"
    chk plan-file-status "$(grep -c '^status: handoff' "$pf")" "1"
    hwhits=$(grep -c -e 'PC/SC reader' -e 'sysmoUSIM' -e 'SMSC' -e 'eUICC' "$pf" || true)
    chk plan-file-hardware "$([[ "${hwhits:-0}" -gt 0 ]] && echo yes || echo no)" "yes"
    pf=$(find "$SIM_PLAN_DIR" -name 'plan_sat-wib_*.txt' | head -n1)
    hwhits=$(grep -c 'sysmoUSIM-SJS1' "$pf" || true)
    chk plan-sat-hardware "$([[ "${hwhits:-0}" -ge 1 ]] && echo yes || echo no)" "yes"
    pf=$(find "$SIM_PLAN_DIR" -name 'plan_esim-download_*.txt' | head -n1)
    hwhits=$(grep -c 'SM-DP+' "$pf" || true)
    chk plan-esim-hardware "$([[ "${hwhits:-0}" -gt 0 ]] && echo yes || echo no)" "yes"
    chk plan-unknown-rc "$(sim_plan nope >/dev/null 2>&1; echo $?)" "2"
    chk plan-missing-rc "$(sim_cmd_plan >/dev/null 2>&1; echo $?)" "2"
    chk plan-count      "$(find "$SIM_PLAN_DIR" -type f | wc -l | tr -d ' ')" "3"

    # ── 12. APDU log ────────────────────────────────────────────────────
    sim_log_init
    chk log-header-col2   "$(head -n1 "$SIM_APDU_LOG" | awk -F'\t' '{print $2}')" "direction"
    chk log-header-fields "$(head -n1 "$SIM_APDU_LOG" | awk -F'\t' '{print NF}')" "7"
    sim_cmd_build_apdu A0 B0 00 00 '' 0A >/dev/null
    chk log-after-build "$(( $(sim_log_count) >= 1 ))" "1"
    chk log-row-fields  "$(tail -n1 "$SIM_APDU_LOG" | awk -F'\t' '{print NF}')" "7"

    # ── 13. Verb argument validation ────────────────────────────────────
    chk cmd-build-missing  "$(sim_cmd_build_apdu A0 A4 >/dev/null 2>&1; echo $?)" "2"
    chk cmd-parse-missing  "$(sim_cmd_parse_apdu >/dev/null 2>&1; echo $?)" "2"
    chk cmd-iccid-missing  "$(sim_cmd_decode_iccid >/dev/null 2>&1; echo $?)" "2"
    chk cmd-imsi-missing   "$(sim_cmd_decode_imsi  >/dev/null 2>&1; echo $?)" "2"
    chk cmd-ota-missing    "$(sim_cmd_parse_ota   >/dev/null 2>&1; echo $?)" "2"
    chk cmd-ad-missing     "$(sim_cmd_decode_ad   >/dev/null 2>&1; echo $?)" "2"
    chk cmd-select-missing "$(sim_cmd_select >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-unknown   "$(sim_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    chk dispatch-empty     "$(sim_cli_main >/dev/null 2>&1; echo $?)" "2"

    # A successful command parse returns 0; a failing status word returns 3.
    chk cmd-parse-capdu-rc "$(sim_cmd_parse_apdu A0A40000023F00 >/dev/null 2>&1; echo $?)" "0"
    chk cmd-parse-sw-ok    "$(sim_cmd_parse_apdu 9000 >/dev/null 2>&1; echo $?)" "0"
    chk cmd-parse-sw-bad   "$(sim_cmd_parse_apdu 6A82 >/dev/null 2>&1; echo $?)" "3"
    chk cmd-ota-rc         "$(sim_cmd_parse_ota "$ota" >/dev/null 2>&1; echo $?)" "0"
    chk cmd-ota-not-ota    "$(sim_cmd_parse_ota "040B912143658709F140F6412021325476980A" >/dev/null 2>&1; echo $?)" "1"

    # ── 14. Sanitisation: a tab in untrusted text must not forge a row ──
    local evil
    evil=$(sim_sanitize $'evil\tname\r\nsecond')
    chk sanitize-no-tabs "$(printf '%s' "$evil" | tr -d '\t\r\n' | wc -c | tr -d ' ')" \
        "$(printf '%s' "$evil" | wc -c | tr -d ' ')"
    sim_log_apdu "C-APDU" "AABB" "1" "-" "-" $'note\twith\ttabs'
    chk log-sanitized-fields "$(tail -n1 "$SIM_APDU_LOG" | awk -F'\t' '{print NF}')" "7"

    # ── 15. Status TSV contract ─────────────────────────────────────────
    out=$(sim_cli_status_tsv)
    chk status-dir   "$(fld "$out" dir)"        "$SIM_DIR"
    chk status-log   "$(fld "$out" apdu_log)"   "$SIM_APDU_LOG"
    chk status-plans "$(fld "$out" plan_count)" "3"

    # ── 16. DPA model (COMP128-1) ───────────────────────────────────────
    # The arithmetic lives in tools/gsm_crypto.py, whose --selftest proves it
    # against held-out challenges. These check this module's delegation and the
    # delegation's argument validation.
    chk dpa-plan-hardware "$(sim_plan_hardware dpa-lab | grep -c oscilloscope)" "1"
    chk dpa-model-bad-ki  "$(sim_dpa_model zz 00112233445566778899aabbccddeeff >/dev/null 2>&1; echo $?)" "2"
    chk dpa-model-no-rand "$(sim_dpa_model 465b5ce8b199b49faa5f0a2ee238a6bc >/dev/null 2>&1; echo $?)" "2"
    chk dpa-sim-bad-sigma "$(sim_dpa_sim 465b5ce8b199b49faa5f0a2ee238a6bc 16 x >/dev/null 2>&1; echo $?)" "2"
    out=$(sim_dpa_model 465b5ce8b199b49faa5f0a2ee238a6bc 23553cbe9637a89d218ae64dae47bf35)
    chk dpa-level0-addr "$(fld "$out" pos_00)" "ki=46 rand=23 addr=140 t0=0F hw=4"
    chk dpa-positions   "$(fld "$out" positions)" "16"
    out=$(sim_dpa_sim 465b5ce8b199b49faa5f0a2ee238a6bc 128 1.0)
    chk dpa-sim-recovers "$(fld "$out" recovered_ki)" "465B5CE8B199B49FAA5F0A2EE238A6BC"
    chk dpa-sim-no-wrong "$(fld "$out" bytes_wrong)" "0"
    chk dpa-sim-holdout  "$(fld "$out" holdout_mismatches)" "0"
    chk dpa-sim-honest   "$(fld "$out" scope)" "synthetic traces from a leakage model, not a measured card"


    # ── 17. SIM authentication known answers ────────────────────────────
    # The check verb carries its own provenance labels: std- rows are fixed by
    # 3GPP TS 35.208 (Milenage test set 1), tool- rows come from the tables in
    # tools/gsm_crypto.py, cli- rows pin the CLI path's RES_sz=64 TUAK output.
    out=$(sim_cmd_sim_auth_check)
    chk auth-check-rc      "$?" "0"
    chk auth-check-pass-n  "$(printf '%s\n' "$out" | grep '	PASS$' | grep -vc '^RESULT')" "31"
    chk auth-check-no-fail "$(printf '%s\n' "$out" | grep -c '	FAIL')" "0"
    chk auth-check-result  "$(fld "$out" RESULT)" "PASS"
    # TS 35.208 test set 1, every field the standard fixes for that set.
    chk auth-set1-opc     "$(fld "$out" std-ts35208-set1-opc)"    "PASS"
    chk auth-set1-f1      "$(fld "$out" std-ts35208-set1-f1)"     "PASS"
    chk auth-set1-f1star  "$(fld "$out" std-ts35208-set1-f1star)" "PASS"
    chk auth-set1-f2      "$(fld "$out" std-ts35208-set1-f2)"     "PASS"
    chk auth-set1-f3      "$(fld "$out" std-ts35208-set1-f3)"     "PASS"
    chk auth-set1-f4      "$(fld "$out" std-ts35208-set1-f4)"     "PASS"
    chk auth-set1-f5      "$(fld "$out" std-ts35208-set1-f5)"     "PASS"
    chk auth-set1-f5star  "$(fld "$out" std-ts35208-set1-f5star)" "PASS"
    chk auth-set1-autn    "$(fld "$out" std-ts35208-set1-autn)"   "PASS"
    chk auth-comp128v1    "$(fld "$out" tool-comp128v1-tv1-sres)" "PASS"
    # v2 and v3 must stay distinguishable: same SRES, different Kc tail.
    chk auth-comp128v2    "$(fld "$out" tool-comp128v2-tv1-kc)"   "PASS"
    chk auth-comp128v3    "$(fld "$out" tool-comp128v3-tv1-kc)"   "PASS"
    chk auth-tuak-topc    "$(fld "$out" tool-tuak-tv1-topc)"      "PASS"
    chk auth-tuak-f1      "$(fld "$out" tool-tuak-tv1-f1)"        "PASS"

    # The verb's own rows: computed values, correct lengths, and the honesty
    # rows a claim audit looks for.
    out=$(sim_cmd_sim_auth comp128-1 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF)
    chk auth-v1-algorithm "$(fld "$out" algorithm)" "comp128-1"
    chk auth-v1-sres      "$(fld "$out" sres)" "04A66BA8"
    chk auth-v1-kc        "$(fld "$out" kc)"   "F87EB8222CEA3400"
    chk auth-v1-no-ck     "$(printf '%s\n' "$out" | grep -c '^ck	')" "0"
    chk auth-v1-limit     "$(printf '%s\n' "$out" | grep -c '^limit	COMP128 defines SRES')" "1"
    out=$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 \
            --opc CD63CB71954A9F4E48A5994E37A02BAF --sqn FF9BB4D0B607 --amf B9B9)
    chk auth-mil-opc      "$(fld "$out" opc)" "CD63CB71954A9F4E48A5994E37A02BAF"
    chk auth-mil-res      "$(fld "$out" res)" "A54211D5E3BA50BF"
    chk auth-mil-ck       "$(fld "$out" ck)"  "B40BA9A3C58B2A05BBF0D987B21BF8CB"
    chk auth-mil-ik       "$(fld "$out" ik)"  "F769BCD751044604127672711C6D3441"
    chk auth-mil-ak       "$(fld "$out" ak)"  "AA689C648370"
    chk auth-mil-mac-s    "$(fld "$out" mac_s)" "01CFAF9EC4E871E9"
    chk auth-mil-autn     "$(fld "$out" autn)" "55F328B43577B9B94A9FFAC354DFAFB3"
    chk auth-mil-autn-basis "$(printf '%s\n' "$out" | grep -c '^autn_basis	SQN xor f5')" "1"
    chk auth-mil-limit-auts "$(printf '%s\n' "$out" | grep -c '^limit	this run emits f1..f5\*; the AUTN is assembled')" "1"
    # Without SQN/AMF there is no f1 and no AUTN: the verb must say so, not
    # print an empty row.
    out=$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 \
            --opc CD63CB71954A9F4E48A5994E37A02BAF)
    chk auth-mil-no-sqn-note  "$(printf '%s\n' "$out" | grep -c '^note	f1, f1\* and therefore AUTN')" "1"
    chk auth-mil-no-autn-row  "$(printf '%s\n' "$out" | grep -c '^autn	')" "0"
    out=$(sim_cmd_sim_auth tuak ABABABABABABABABABABABABABABABAB 42424242424242424242424242424242 \
            --top 5555555555555555555555555555555555555555555555555555555555555555 --sqn 111111111111 --amf FFFF)
    chk auth-tuak-topc-v   "$(fld "$out" topc)" "BD04D9530E87513C5D837AC2AD954623A8E2330C115305A73EB45D1F40CCCBFF"
    chk auth-tuak-key-bits "$(fld "$out" key_bits)" "128"
    chk auth-tuak-res-sz   "$(printf '%s\n' "$out" | grep -c '^limit	TUAK MAC_sz/RES_sz/CK_sz/IK_sz are per-vector')" "1"
    # 256-bit K is a 64-hex key; the length check must follow --klength.
    chk auth-tuak-256-rc   "$(sim_cmd_sim_auth tuak ABABABABABABABABABABABABABABABAB 42424242424242424242424242424242 --top 5555555555555555555555555555555555555555555555555555555555555555 --klength 256 >/dev/null 2>&1; echo $?)" "2"
    # Argument validation.
    chk auth-both-op-opc   "$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 --op CDC202D5123E20F62B6D676AC72CB318 --opc CD63CB71954A9F4E48A5994E37A02BAF >/dev/null 2>&1; echo $?)" "2"
    chk auth-bad-klength   "$(sim_cmd_sim_auth tuak ABABABABABABABABABABABABABABABAB 42424242424242424242424242424242 --top 5555555555555555555555555555555555555555555555555555555555555555 --klength 192 >/dev/null 2>&1; echo $?)" "2"
    chk auth-bad-sqn       "$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64DAE47BF35 --opc CD63CB71954A9F4E48A5994E37A02BAF --sqn ZZ >/dev/null 2>&1; echo $?)" "2"
    chk auth-short-rand    "$(sim_cmd_sim_auth comp128-1 00112233445566778899AABBCCDDEEFF 0011 >/dev/null 2>&1; echo $?)" "2"
    chk auth-unknown-flag  "$(sim_cmd_sim_auth comp128-1 00112233445566778899AABBCCDDEEFF 00112233445566778899AABBCCDDEEFF --nope >/dev/null 2>&1; echo $?)" "2"
    # AUTN assembly is a real XOR, not string concatenation.
    chk auth-xor-ff00      "$(sim_auth_xor FF00 AA55)" "5555"
    chk auth-xor-sqnak     "$(sim_auth_xor FF9BB4D0B607 AA689C648370)" "55F328B43577"
    chk auth-xor-len-mismatch "$(sim_auth_xor FF AA55 >/dev/null 2>&1; echo $?)" "1"

    # ── 18. SGP.22 ES9+ request builder (nothing is sent) ───────────────
    # The builder is deterministic (fixed key order, no whitespace), so the
    # exact body text is part of the contract and is asserted byte for byte.
    local i_json='{"euiccChallenge":"AAECAwQFBgcICQoLDA0ODw==","euiccInfo1":"MBCgC4ABAoECA4IEAQA=","smdpAddress":"smdp.example.com"}'
    local i_url="https://smdp.example.com/gsma/rsp2/es9plus/initiateAuthentication"
    out=$(sim_cmd_es9_plus initiateAuthentication --smds smdp.example.com \
            --euicc-challenge 000102030405060708090A0B0C0D0E0F --euicc-info1 3010A00B80010281020382040100)
    chk es9-init-method    "$(fld "$out" method)" "POST"
    chk es9-init-path      "$(fld "$out" path)" "/gsma/rsp2/es9plus/initiateAuthentication"
    chk es9-init-url       "$(fld "$out" url)" "$i_url"
    chk es9-init-host      "$(fld "$out" header_host)" "Host: smdp.example.com"
    chk es9-init-ua        "$(fld "$out" header_user_agent)" "User-Agent: gsma-rsp-lpad"
    chk es9-init-proto     "$(fld "$out" header_admin_protocol)" "X-Admin-Protocol: gsma/rsp/v2.2.2"
    chk es9-init-ctype     "$(fld "$out" header_content_type)" "Content-Type: application/json"
    chk es9-init-clen      "$(fld "$out" header_content_length)" "Content-Length: 114"
    chk es9-init-bytes     "$(fld "$out" body_bytes)" "114"
    chk es9-init-json      "$(fld "$out" json)" "$i_json"
    chk es9-init-json-len  "$(printf '%s' "$i_json" | wc -c | tr -d ' ')" "114"
    chk es9-init-no-header "$(printf '%s' "$(fld "$out" json)" | grep -c 'header')" "0"
    chk es9-init-curl      "$(fld "$out" curl)" \
        "curl -sS --http1.1 -X POST '$i_url' -H 'Host: smdp.example.com' -H 'User-Agent: gsma-rsp-lpad' -H 'X-Admin-Protocol: gsma/rsp/v2.2.2' -H 'Content-Type: application/json' -H 'Content-Length: 114' --data-binary '$i_json'"
    chk es9-init-sent      "$(fld "$out" sent)" "0"
    chk es9-init-scope     "$(printf '%s\n' "$out" | grep -c '^scope	SGP.22 ES9+ HTTP/JSON request builder; nothing is transmitted')" "1"
    chk es9-init-spec      "$(printf '%s\n' "$out" | grep -c '^spec	SGP.22 v2.2.2 6.5.2.6')" "1"
    chk es9-init-expects   "$(printf '%s\n' "$out" | grep -c '^expects	200 + JSON: header.functionExecutionStatus, transactionId, serverSigned1')" "1"
    # Deterministic: two runs are byte-identical.
    out2=$(sim_cmd_es9_plus initiateAuthentication --smds smdp.example.com \
            --euicc-challenge 000102030405060708090A0B0C0D0E0F --euicc-info1 3010A00B80010281020382040100)
    chk es9-init-stable    "$([[ "$out" == "$out2" ]] && echo yes || echo no)" "yes"

    out=$(sim_cmd_es9_plus authenticateClient --smds smdp.example.com:8443 \
            --transaction-id 0123456789abcdef --authenticate-server-response 3000)
    chk es9-authc-json   "$(fld "$out" json)" '{"transactionId":"0123456789ABCDEF","authenticateServerResponse":"MAA="}'
    chk es9-authc-path   "$(fld "$out" path)" "/gsma/rsp2/es9plus/authenticateClient"
    chk es9-authc-url    "$(fld "$out" url)" "https://smdp.example.com:8443/gsma/rsp2/es9plus/authenticateClient"
    chk es9-authc-host   "$(fld "$out" header_host)" "Host: smdp.example.com:8443"
    chk es9-authc-clen   "$(fld "$out" header_content_length)" "Content-Length: 72"
    chk es9-authc-txn-upper "$(printf '%s' "$(fld "$out" json)" | grep -c '0123456789ABCDEF')" "1"
    chk es9-authc-sent   "$(fld "$out" sent)" "0"

    out=$(sim_cmd_es9_plus getBoundProfilePackage --smds smdp.example.com \
            --transaction-id 0123456789ABCDEF --prepare-download-response 3000)
    chk es9-bpp-json     "$(fld "$out" json)" '{"transactionId":"0123456789ABCDEF","prepareDownloadResponse":"MAA="}'
    chk es9-bpp-path     "$(fld "$out" path)" "/gsma/rsp2/es9plus/getBoundProfilePackage"
    chk es9-bpp-clen     "$(fld "$out" header_content_length)" "Content-Length: 69"
    chk es9-bpp-sent     "$(fld "$out" sent)" "0"

    out=$(sim_cmd_es9_plus cancelSession --smds smdp.example.com \
            --transaction-id 0123456789ABCDEF --cancel-session-response 3000)
    chk es9-cancel-json  "$(fld "$out" json)" '{"transactionId":"0123456789ABCDEF","cancelSessionResponse":"MAA="}'
    chk es9-cancel-path  "$(fld "$out" path)" "/gsma/rsp2/es9plus/cancelSession"
    chk es9-cancel-clen  "$(fld "$out" header_content_length)" "Content-Length: 67"
    chk es9-cancel-no-body "$(printf '%s\n' "$out" | grep -c '^expects	200 with no JSON body')" "1"
    chk es9-cancel-sent  "$(fld "$out" sent)" "0"

    # What must be refused, and what must be announced rather than emitted.
    chk es9-reject-unknown   "$(sim_cmd_es9_plus nonsense --smds h >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-hnotif    "$(sim_cmd_es9_plus handleNotification --smds h >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-no-smds   "$(sim_cmd_es9_plus initiateAuthentication --euicc-challenge 00112233445566778899AABBCCDDEEFF --euicc-info1 3000 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-no-ec     "$(sim_cmd_es9_plus initiateAuthentication --smds h --euicc-info1 3000 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-bad-ec    "$(sim_cmd_es9_plus initiateAuthentication --smds h --euicc-challenge 0011 --euicc-info1 3000 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-no-info   "$(sim_cmd_es9_plus initiateAuthentication --smds h --euicc-challenge 00112233445566778899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-both-ch   "$(sim_cmd_es9_plus initiateAuthentication --smds h --euicc-challenge 00112233445566778899AABBCCDDEEFF --client-challenge 00112233445566778899AABBCCDDEEFF --euicc-info1 3000 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-bad-txn   "$(sim_cmd_es9_plus cancelSession --smds h --transaction-id ZZ-- --cancel-session-response 3000 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-no-resp   "$(sim_cmd_es9_plus getBoundProfilePackage --smds h --transaction-id 01 >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-odd-hex   "$(sim_cmd_es9_plus getBoundProfilePackage --smds h --transaction-id 01 --prepare-download-response ABC >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-bad-eid   "$(sim_cmd_es9_plus cancelSession --smds h --transaction-id 01 --cancel-session-response 3000 --eid XYZ >/dev/null 2>&1; echo $?)" "2"
    chk es9-reject-bad-flag  "$(sim_cmd_es9_plus cancelSession --smds h --transaction-id 01 --cancel-session-response 3000 --nope >/dev/null 2>&1; echo $?)" "2"
    out=$(sim_cmd_es9_plus authenticateClient --smds smdp.example.com --transaction-id 01 \
            --authenticate-server-response 3000 --eid 89049032000000000000000000000001 \
            --matching-id ORD-1 --server-challenge AABB)
    chk es9-eid-announced  "$(printf '%s\n' "$out" | grep -c '^limit	eid 89049032000000000000000000000001: not a field of any ES9+')" "1"
    chk es9-mid-announced  "$(printf '%s\n' "$out" | grep -c '^limit	matchingId ORD-1: not a field')" "1"
    chk es9-schal-announced "$(printf '%s\n' "$out" | grep -c '^limit	serverChallenge: an ES10b.AuthenticateServer input')" "1"
    chk es9-eid-not-emitted "$(printf '%s' "$(fld "$out" json)" | grep -c '89049032')" "0"
    out=$(sim_cmd_es9_plus cancelSession --smds smdp.example.com --transaction-id 01 \
            --cancel-session-response 3000 --authenticate-server-response 3000 --euicc-challenge 00112233445566778899AABBCCDDEEFF)
    chk es9-wrong-op-resp  "$(printf '%s\n' "$out" | grep -c '^limit	--authenticate-server-response is 4 hex digits but ES9+.CancelSession does not carry it')" "1"
    chk es9-wrong-op-ec    "$(printf '%s\n' "$out" | grep -c '^limit	--euicc-challenge is 32 hex digits but only initiateAuthentication carries it')" "1"
    chk es9-limit-es2      "$(printf '%s\n' "$out" | grep -c 'ES2+ (6.5.2.1..6.5.2.5) and ES10b/ES10c (5.7) are not implemented')" "1"
    chk es9-limit-es10     "$(printf '%s\n' "$out" | grep -c 'ES10b run (5.7.7 GetEUICCChallenge')" "1"

    # --out writes the curl command to a file; the tree still sends nothing.
    local es9f="$d/es9_request.sh"
    out=$(sim_cmd_es9_plus cancelSession --smds smdp.example.com --transaction-id 01 \
            --cancel-session-response 3000 --out "$es9f")
    chk es9-out-row    "$(fld "$out" out)" "$es9f"
    chk es9-out-exists "$([[ -f "$es9f" ]] && echo yes || echo no)" "yes"
    chk es9-out-shebang "$(head -n1 "$es9f")" "#!/bin/sh"
    chk es9-out-curl-n "$(grep -c '^curl -sS --http1.1 -X POST' "$es9f")" "1"
    chk es9-out-sent   "$(grep -c 'sent 0 when written' "$es9f")" "1"
    chk es9-out-spec   "$(grep -c '6.5.2.10' "$es9f")" "1"


    # ── 19. SGP.22 ES8+ TLV builder: every octet from a clause it names ──
    # The hex asserted below is exactly the octets the cited clause names --
    # tag, length and value -- so a moved tag or a changed length form fails
    # here instead of looking plausible in an operator's hands.
    out=$(sim_cmd_es8_build configure-isdp --dp-oid 1.2.840.113549)
    chk es8-isdp-hex      "$(fld "$out" hex)" "BF240AB80806062A864886F70D"
    chk es8-isdp-bytes    "$(fld "$out" bytes)" "13"
    chk es8-isdp-status   "$(fld "$out" status)" "built"
    chk es8-isdp-bf24-ref "$(printf '%s\n' "$out" | grep -c '^ref	ConfigureISDPRequest	BF24	5.5.2')" "1"
    chk es8-isdp-b8-ref   "$(printf '%s\n' "$out" | grep -c '^ref	dpProprietaryData	B8	5.5.2')" "1"
    chk es8-isdp-oid-row  "$(printf '%s\n' "$out" | grep -c '^field	BF24.dpProprietaryData.dpOid	06	OBJECT IDENTIFIER	1.2.840.113549	5.5.2')" "1"
    # dpProprietaryData is OPTIONAL (5.5.2): with no --dp-oid the only lawful
    # encoding is the empty SEQUENCE, BF24 00.
    out=$(sim_cmd_es8_build configure-isdp)
    chk es8-isdp-empty    "$(fld "$out" hex)" "BF2400"
    chk es8-isdp-opt-note "$(printf '%s\n' "$out" | grep -c 'dpProprietaryData is OPTIONAL (5.5.2)')" "1"
    # X.690 8.19: first arc 0..2, and below 2 the second arc must stay < 40.
    chk es8-isdp-arc1     "$(sim_cmd_es8_build configure-isdp --dp-oid 3.1 >/dev/null 2>&1; echo $?)" "2"
    chk es8-isdp-arc2     "$(sim_cmd_es8_build configure-isdp --dp-oid 1.40 >/dev/null 2>&1; echo $?)" "2"
    chk es8-isdp-not-oid  "$(sim_cmd_es8_build configure-isdp --dp-oid 1.2.x >/dev/null 2>&1; echo $?)" "2"

    # StoreMetadata (5.5.3). The iccid is the ten EFiccid octets, emitted
    # unchanged behind 5A -- the BCD swap happened when EF_ICCID was written.
    out=$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 \
            --service-provider-name GSMA_TEST --profile-name GSMA_TEST_PROFILE --profile-class test)
    chk es8-md-hex        "$(fld "$out" hex)" "BF252D5A0A98001032547698103214910947534D415F54455354921147534D415F544553545F50524F46494C45950100"
    chk es8-md-bytes      "$(fld "$out" bytes)" "48"
    chk es8-md-iccid-ref  "$(printf '%s\n' "$out" | grep -c '^ref	iccid	5A	5.5.3')" "1"
    chk es8-md-spn-ref    "$(printf '%s\n' "$out" | grep -c '^ref	serviceProviderName	91	5.5.3')" "1"
    chk es8-md-name-ref   "$(printf '%s\n' "$out" | grep -c '^ref	profileName	92	5.5.3')" "1"
    chk es8-md-class-ref  "$(printf '%s\n' "$out" | grep -c '^ref	profileClass	95	5.5.3')" "1"
    # profileOwner [23] -> B7 { 80 mccMnc }; PprIds -> 99 02 0640 for ppr1.
    out=$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --profile-owner 42F618 --ppr ppr1)
    chk es8-md-owner-ppr  "$(fld "$out" hex)" "BF25175A0A98001032547698103214B705800342F61899020640"
    chk es8-md-owner-note "$(printf '%s\n' "$out" | grep -c 'AUTOMATIC TAGS assigns the untagged member')" "1"
    out=$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --ppr pprUpdateControl,ppr1)
    chk es8-md-ppr-bits   "$(printf '%s' "$(fld "$out" hex)" | grep -c '990206C0$')" "1"
    # notificationConfigurationInfo [22] -> B6 { SEQUENCE { 80 event, 81 fqdn } }.
    out=$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --notification install=smdp.example.com)
    chk es8-md-notif      "$(fld "$out" hex)" "BF25265A0A98001032547698103214B6183016800207808110736D64702E6578616D706C652E636F6D"
    chk es8-md-notif-note "$(printf '%s\n' "$out" | grep -c 'the SEQUENCE members of NotificationConfigurationInformation (5.5.3) carry no tags')" "1"
    out=$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --icon-type png --icon 89504E47)
    chk es8-md-icon       "$(fld "$out" hex)" "BF25155A0A98001032547698103214930101940489504E47"
    # A missing mandatory member hands off; a wrong one is refused.
    chk es8-md-no-iccid   "$(sim_cmd_es8_build store-metadata >/dev/null 2>&1; echo $?)" "3"
    chk es8-md-no-iccid-lim "$(sim_cmd_es8_build store-metadata 2>/dev/null | grep -c 'missing input: --iccid')" "1"
    chk es8-md-short-iccid "$(sim_cmd_es8_build store-metadata --iccid 980010325476981032 >/dev/null 2>&1; echo $?)" "1"
    chk es8-md-icon-ality  "$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --icon 8950 >/dev/null 2>&1; echo $?)" "1"
    chk es8-md-bad-ppr    "$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --ppr ppr9 >/dev/null 2>&1; echo $?)" "2"
    # SCP03t (SGP.02 4.1.3.3). The session keys and the two cryptograms are the
    # Annex D derivation over this key material and this context; the '84' TLV
    # is the key version, the mandatory zero key id, and the host challenge.
    out=$(sim_cmd_es8_scp03t --k-enc 000102030405060708090A0B0C0D0E0F \
              --k-mac 101112131415161718191A1B1C1D1E1F \
              --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
              --payload BF2401020304)
    chk scp03t-s-enc      "$(printf '%s\n' "$out" | sed -n 's/^s_enc[[:space:]]*//p')" "1771157962A029C5435A1AC81D0B9806"
    chk scp03t-s-mac      "$(printf '%s\n' "$out" | sed -n 's/^s_mac[[:space:]]*//p')" "3E994A1F2EAF7182282B2E5ED3870B83"
    chk scp03t-s-rmac     "$(printf '%s\n' "$out" | sed -n 's/^s_rmac[[:space:]]*//p')" "49214B50BD45D69A2FEB47C69DE5407E"
    chk scp03t-card-cgram "$(printf '%s\n' "$out" | sed -n 's/^card_cryptogram[[:space:]]*//p')" "D71A889EFCF709E8"
    chk scp03t-host-cgram "$(printf '%s\n' "$out" | sed -n 's/^host_cryptogram[[:space:]]*//p')" "75A94E14D36602F1"
    chk scp03t-tlv-84     "$(printf '%s\n' "$out" | sed -n 's/^tlv_84[[:space:]]*//p')" "840A30000011223344556677"
    chk scp03t-tlv-85     "$(printf '%s\n' "$out" | sed -n 's/^tlv_85[[:space:]]*//p')" "85113375A94E14D36602F17AF2A1E33C4D3206"
    chk scp03t-tlv-86     "$(printf '%s\n' "$out" | grep -c '^tlv_86_1	8618')" "1"
    chk scp03t-level      "$(printf '%s\n' "$out" | grep -c "SHALL be '33'")" "1"
    chk scp03t-no-card    "$(printf '%s\n' "$out" | grep -c 'is what the derivation predicts, not what a card confirmed')" "1"
    chk scp03t-needs-keys "$(sim_cmd_es8_scp03t --k-enc 000102030405060708090A0B0C0D0E0F >/dev/null 2>&1; echo $?)" "3"
    chk scp03t-short-key  "$(sim_cmd_es8_scp03t --k-enc 000102030405060708090A0B0C0D0E --k-mac 101112131415161718191A1B1C1D1E1F --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "1"
    chk es8-md-bad-class  "$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --profile-class gold >/dev/null 2>&1; echo $?)" "2"
    chk es8-md-bad-event  "$(sim_cmd_es8_build store-metadata --iccid 98001032547698103214 --notification reboot=x >/dev/null 2>&1; echo $?)" "2"

    # ReplaceSessionKeys (5.5.4): the three untagged members become 80/81/82
    # because Annex A declares AUTOMATIC TAGS.
    out=$(sim_cmd_es8_build replace-session-keys --mac-chaining 00112233445566778899AABBCCDDEEFF \
            --ppk-enc 0102030405060708090A0B0C0D0E0F10 --ppk-cmac 1112131415161718191A1B1C1D1E1F20)
    chk es8-rsk-hex       "$(fld "$out" hex)" "BF2636801000112233445566778899AABBCCDDEEFF81100102030405060708090A0B0C0D0E0F1082101112131415161718191A1B1C1D1E1F20"
    chk es8-rsk-bytes     "$(fld "$out" bytes)" "57"
    chk es8-rsk-automatic "$(printf '%s\n' "$out" | grep -c 'tag 8[012] by AUTOMATIC TAGS')" "2"
    chk es8-rsk-missing   "$(sim_cmd_es8_build replace-session-keys --mac-chaining 00 >/dev/null 2>&1; echo $?)" "3"
    chk es8-rsk-short     "$(sim_cmd_es8_build replace-session-keys --mac-chaining 00112233445566778899AABBCCDDEE --ppk-enc 00112233445566778899AABBCCDDEEFF --ppk-cmac 00112233445566778899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "1"

    # InitialiseSecureChannel (5.5.1) inside the BF36 header of 2.5.4. The
    # 174-octet shape is the one a real SM-DP+ BPP starts with:
    #   BF36 81 AA  BF23 81 A6  82 01 01  80 10 <txn>
    #   A6 10 80 01 88 81 01 10 84 08 <host>  5F49 41 04 <64>  5F37 40 <64>
    local otpk="04$(printf '11%.0s' {1..64})"
    local sig="$(printf '22%.0s' {1..64})"
    out=$(sim_cmd_es8_build bpp-header --transaction-id 0123456789ABCDEF --host-id 6D61686C7A656974 \
            --smdp-otpk "$otpk" --smdp-sign "$sig")
    chk es8-bf23-hex      "$(fld "$out" hex)" "BF3681AABF2381A682010180080123456789ABCDEFA61080018881011084086D61686C7A6569745F494104$(printf '11%.0s' {1..64})5F3740$(printf '22%.0s' {1..64})"
    chk es8-bf23-bytes    "$(fld "$out" bytes)" "174"
    chk es8-bf23-crt-ref  "$(printf '%s\n' "$out" | grep -c '^ref	controlRefTemplate	A6	5.5.1: controlRefTemplate \[6\] IMPLICIT')" "1"
    out=$(sim_cmd_es8_build initialise-secure-channel --transaction-id 01 --host-id 00 --smdp-otpk "$otpk" --smdp-sign "$sig")
    chk es8-bf23-no-bf36  "$(printf '%s' "$(fld "$out" hex)" | cut -c1-6)" "BF2381"
    chk es8-bf23-missing  "$(sim_cmd_es8_build bpp-header --transaction-id 01 --host-id 00 --smdp-otpk "$otpk" >/dev/null 2>&1; echo $?)" "3"
    chk es8-bf23-miss-lim "$(sim_cmd_es8_build bpp-header --transaction-id 01 --host-id 00 --smdp-otpk "$otpk" 2>/dev/null | grep -c 'missing input: --smdp-sign')" "1"
    chk es8-bf23-long-txn "$(sim_cmd_es8_build bpp-header --transaction-id 00112233445566778899AABBCCDDEEFF11 --host-id 00 --smdp-otpk "$otpk" --smdp-sign "$sig" >/dev/null 2>&1; echo $?)" "1"
    chk es8-bf23-bad-otpk "$(sim_cmd_es8_build bpp-header --transaction-id 01 --host-id 00 --smdp-otpk 04 --smdp-sign "$sig" >/dev/null 2>&1; echo $?)" "1"

    # The segment wrappers: A0 firstSequenceOf87, A1 sequenceOf88, A3
    # sequenceOf86, each carrying its own tag+length around the '87'/'88'/'86'.
    chk es8-seg-87        "$(fld "$(sim_cmd_es8_build sequence-87 --payload 8701AA)" hex)" "A0038701AA"
    chk es8-seg-88        "$(fld "$(sim_cmd_es8_build sequence-88 --payload 8801BB)" hex)" "A1038801BB"
    chk es8-seg-86        "$(fld "$(sim_cmd_es8_build sequence-86 --payload 8601DD)" hex)" "A3038601DD"
    chk es8-seg-no-payload "$(sim_cmd_es8_build sequence-87 >/dev/null 2>&1; echo $?)" "3"
    # A profile element is not a segment: SCP03t protects it first, and that
    # protection (SGP.02) is not built here, so the builder hands off.
    chk es8-seg-not-seg   "$(sim_cmd_es8_build sequence-87 --payload BF2400 >/dev/null 2>&1; echo $?)" "3"
    chk es8-seg-lim       "$(sim_cmd_es8_build sequence-87 --payload BF2400 2>/dev/null | grep -c 'SCP03t protection runs over it first')" "1"
    chk es8-seg-not-hex   "$(sim_cmd_es8_build sequence-87 --payload ZZ >/dev/null 2>&1; echo $?)" "1"

    # The whole BPP in the order 2.5.4 states:
    #   BF36 { BF23, A0 '87', A1 '88', A2 '87' OPTIONAL, A3 '86' }
    out=$(sim_cmd_es8_build bpp --transaction-id 0123456789ABCDEF --host-id 6D61686C7A656974 \
            --smdp-otpk "$otpk" --smdp-sign "$sig" --first-87 8701AA --88 8801BB \
            --second-87 8701CC --86 8601DD)
    chk es8-bpp-len       "$(printf '%s' "$(fld "$out" hex)" | wc -c | tr -d ' ')" "388"
    chk es8-bpp-prefix    "$(printf '%s' "$(fld "$out" hex)" | cut -c1-16)" "BF3681BEBF2381A6"
    chk es8-bpp-order     "$(printf '%s' "$(fld "$out" hex)" | grep -c 'A0038701AAA1038801BBA2038701CCA3038601DD$')" "1"
    chk es8-bpp-missing   "$(sim_cmd_es8_build bpp --transaction-id 01 --host-id 00 --smdp-otpk "$otpk" --smdp-sign "$sig" --first-87 8701AA --88 8801BB >/dev/null 2>&1; echo $?)" "3"
    chk es8-bpp-unknown   "$(sim_cmd_es8_build nonsense >/dev/null 2>&1; echo $?)" "2"
    chk es8-bpp-noargs    "$(sim_cmd_es8_build >/dev/null 2>&1; echo $?)" "2"
    chk es8-bpp-badflag   "$(sim_cmd_es8_build configure-isdp --nope 1 >/dev/null 2>&1; echo $?)" "2"

    # ── 20. BPP walker: depth, tag, length, value, clause -- no phone ────
    out=$(sim_cmd_es8_parse "BF240AB80806062A864886F70D"); rc=$?
    chk es8-parse-isdp-rc "$rc" "0"
    chk es8-parse-isdp-root "$(printf '%s\n' "$out" | grep -c '^root	BF24	ConfigureISDPRequest	5.5.2')" "1"
    chk es8-parse-isdp-note "$(printf '%s\n' "$out" | grep -c 'not the BF36 BoundProfilePackage (2.5.4) a whole BPP is')" "1"
    chk es8-parse-isdp-d0 "$(printf '%s\n' "$out" | grep -c '^tlv	0		BF24	10	B80806062A864886F70D')" "1"
    chk es8-parse-isdp-d1 "$(printf '%s\n' "$out" | grep -c '^tlv	1	BF24	B8	8	06062A864886F70D')" "1"
    chk es8-parse-isdp-oid "$(printf '%s\n' "$out" | grep -c '= 1.2.840.113549')" "1"
    chk es8-parse-status  "$(printf '%s\n' "$out" | grep -c '^status	parsed')" "1"
    # A whole BPP down to the segment wrapper and the opaque '87'.
    out=$(sim_cmd_es8_parse "BF3605A0038701AA"); rc=$?
    chk es8-parse-bpp-rc  "$rc" "0"
    chk es8-parse-bpp-a0  "$(printf '%s\n' "$out" | grep -c '^tlv	1	BF36	A0	3	8701AA	BoundProfilePackage.firstSequenceOf87	2.5.4')" "1"
    chk es8-parse-bpp-87  "$(printf '%s\n' "$out" | grep -c '^tlv	2	BF36/A0	87	1	AA	SCP03t payload')" "1"
    # A malformed envelope is an error; an unnamed tag is a handoff, not a guess.
    chk es8-parse-trunc   "$(sim_cmd_es8_parse BF3603A00387 >/dev/null 2>&1; echo $?)" "1"
    chk es8-parse-odd     "$(sim_cmd_es8_parse ABC >/dev/null 2>&1; echo $?)" "2"
    chk es8-parse-noarg   "$(sim_cmd_es8_parse >/dev/null 2>&1; echo $?)" "2"
    out=$(sim_cmd_es8_parse "BF36049F7F01AA"); rc=$?
    chk es8-parse-unk-rc  "$rc" "3"
    chk es8-parse-unk-lim "$(printf '%s\n' "$out" | grep -c 'no clause in SGP.22 v2.2.2 2.5.4 / 5.5.x / 5.7.9 / 5.7.10 names it')" "1"

    # ── 21. ES9+ response bodies (6.5.1.4, 6.5.2.6..6.5.2.10) ───────────
    local iresp='{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"0123456789ABCDEF","serverSigned1":"MAA=","serverSignature1":"MAA=","euiccCiPKIdToBeUsed":"MAA=","serverCertificate":"MAA="}'
    out=$(sim_cmd_es9_response initiateAuthentication "$iresp" --transaction-id 0123456789ABCDEF); rc=$?
    chk es9r-init-rc      "$rc" "0"
    chk es9r-init-op      "$(printf '%s\n' "$out" | grep -c '^op	ES9+.InitiateAuthentication')" "1"
    chk es9r-init-header  "$(printf '%s\n' "$out" | grep -c '^header	functionExecutionStatus.status	Executed-Success')" "1"
    chk es9r-init-txn     "$(printf '%s\n' "$out" | grep -c '^field	transactionId	0123456789ABCDEF')" "1"
    chk es9r-init-fields  "$(printf '%s\n' "$out" | grep -c '^field	\(serverSigned1\|serverSignature1\|euiccCiPKIdToBeUsed\|serverCertificate\)	base64, 2 octets, begins 3000')" "4"
    chk es9r-init-match   "$(printf '%s\n' "$out" | grep -c '^match	transactionId	echoed 0123456789ABCDEF')" "1"
    chk es9r-init-status  "$(printf '%s\n' "$out" | grep -c '^status	parsed')" "1"
    # authenticateClient: profileMetadata is the StoreMetadataRequest (BF25).
    out=$(sim_cmd_es9_response authenticateClient \
        '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"01","profileMetadata":"vyUA","smdpSigned2":"MAA=","smdpSignature2":"MAA=","smdpCertificate":"MAA="}'); rc=$?
    chk es9r-authc-rc     "$rc" "0"
    chk es9r-authc-root   "$(printf '%s\n' "$out" | grep -c '^field	profileMetadata.root	BF25 StoreMetadataRequest')" "1"
    # getBoundProfilePackage: the base64 decodes to a BF36 BoundProfilePackage.
    out=$(sim_cmd_es9_response getBoundProfilePackage \
        '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"01","boundProfilePackage":"vzYFoAOHAao="}'); rc=$?
    chk es9r-bpp-rc       "$rc" "0"
    chk es9r-bpp-root     "$(printf '%s\n' "$out" | grep -c '^field	boundProfilePackage.root	BF36 BoundProfilePackage')" "1"
    chk es9r-bpp-walk     "$(printf '%s\n' "$out" | grep -c '^next	--es8-parse <hex of boundProfilePackage>')" "1"
    chk es9r-bpp-missing  "$(sim_cmd_es9_response getBoundProfilePackage '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"01"}' >/dev/null 2>&1; echo $?)" "3"
    chk es9r-bpp-miss-lim "$(sim_cmd_es9_response getBoundProfilePackage '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"01"}' 2>/dev/null | grep -c 'required field boundProfilePackage missing')" "1"
    # cancelSession: 6.5.2.10 defines no response body, so only the header is checkable.
    out=$(sim_cmd_es9_response cancelSession '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}}}'); rc=$?
    chk es9r-cancel-rc    "$rc" "0"
    chk es9r-cancel-note  "$(printf '%s\n' "$out" | grep -c 'has no JSON body part of the response')" "1"
    # The status object of 6.5.1.4 when the function failed.
    out=$(sim_cmd_es9_response getBoundProfilePackage '{"header":{"functionExecutionStatus":{"status":"Failed","statusCodeData":{"subjectCode":"8.1.1","reasonCode":"3.9","subjectIdentifier":"iccid","message":"no such profile"}}},"transactionId":"AB"}'); rc=$?
    chk es9r-failed-rc    "$rc" "3"
    chk es9r-failed-sub   "$(printf '%s\n' "$out" | grep -c '^header	functionExecutionStatus.statusCodeData.subjectCode	8.1.1')" "1"
    chk es9r-failed-why   "$(printf '%s\n' "$out" | grep -c '^header	functionExecutionStatus.statusCodeData.reasonCode	3.9')" "1"
    chk es9r-failed-id    "$(printf '%s\n' "$out" | grep -c '^header	functionExecutionStatus.statusCodeData.subjectIdentifier	iccid')" "1"
    chk es9r-failed-msg   "$(printf '%s\n' "$out" | grep -c '^header	functionExecutionStatus.statusCodeData.message	no such profile')" "1"
    chk es9r-failed-note  "$(printf '%s\n' "$out" | grep -c 'the function failed; subjectCode/reasonCode above say where')" "1"
    # 6.5.1.4 requires both codes whenever statusCodeData is present.
    chk es9r-scd-short    "$(sim_cmd_es9_response initiateAuthentication '{"header":{"functionExecutionStatus":{"status":"Executed-Success","statusCodeData":{"subjectCode":"1.1"}}},"transactionId":"01","serverSigned1":"MAA=","serverSignature1":"MAA=","euiccCiPKIdToBeUsed":"MAA=","serverCertificate":"MAA="}' >/dev/null 2>&1; echo $?)" "3"
    # The transactionId echo, and every way a body can fail to be a response.
    chk es9r-mismatch     "$(sim_cmd_es9_response cancelSession '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"CD"}' --transaction-id AB >/dev/null 2>&1; echo $?)" "1"
    chk es9r-mismatch-err "$(sim_cmd_es9_response cancelSession '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"CD"}' --transaction-id AB 2>&1 >/dev/null | grep -c '^ERROR	transactionId mismatch')" "1"
    chk es9r-badpat-txn   "$(sim_cmd_es9_response cancelSession '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"xyz"}' >/dev/null 2>&1; echo $?)" "3"
    chk es9r-no-header    "$(sim_cmd_es9_response initiateAuthentication '{"transactionId":"01"}' >/dev/null 2>&1; echo $?)" "1"
    chk es9r-no-fes       "$(sim_cmd_es9_response initiateAuthentication '{"header":{}}' >/dev/null 2>&1; echo $?)" "1"
    chk es9r-no-status    "$(sim_cmd_es9_response initiateAuthentication '{"header":{"functionExecutionStatus":{}}}' >/dev/null 2>&1; echo $?)" "1"
    chk es9r-not-json     "$(sim_cmd_es9_response initiateAuthentication nope >/dev/null 2>&1; echo $?)" "1"
    chk es9r-bad-op       "$(sim_cmd_es9_response nope '{}' >/dev/null 2>&1; echo $?)" "2"
    chk es9r-no-args      "$(sim_cmd_es9_response >/dev/null 2>&1; echo $?)" "2"
    chk es9r-bad-b64      "$(sim_cmd_es9_response initiateAuthentication '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"serverSigned1":"!!!"}' >/dev/null 2>&1; echo $?)" "1"
    chk es9r-unknown-key  "$(sim_cmd_es9_response cancelSession '{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"sneaky":"x"}' 2>/dev/null | grep -c 'not in the 6.5.2.10 schema')" "1"

    # HandleNotification (6.5.2.9): the one ES9+ call --es9-plus still refuses.
    local notif_b64; notif_b64=$(printf 'BF3706BF2703800101' | xxd -r -p | base64 -w0)
    out=$(sim_cmd_es9_notification "{\"pendingNotification\":\"$notif_b64\"}"); rc=$?
    chk es9n-rc           "$rc" "0"
    chk es9n-op           "$(printf '%s\n' "$out" | grep -c '^op	ES9+.HandleNotification')" "1"
    chk es9n-field        "$(printf '%s\n' "$out" | grep -c '^field	pendingNotification	base64 -> 9 octets')" "1"
    chk es9n-root         "$(printf '%s\n' "$out" | grep -c '^root	BF37	ProfileInstallationResult')" "1"
    chk es9n-tlv          "$(printf '%s\n' "$out" | grep -c '^tlv	1	BF37	BF27	3	800101	profileInstallationResultData')" "1"
    chk es9n-expects      "$(printf '%s\n' "$out" | grep -c '204 No Content with an empty body')" "1"
    # OtherSignedNotification is the untagged SEQUENCE alternative of 5.7.10.
    chk es9n-seq-root     "$(sim_cmd_es9_notification '{"pendingNotification":"MAMCAQE="}' 2>/dev/null | grep -c '^root	30	SEQUENCE')" "1"
    chk es9n-no-key       "$(sim_cmd_es9_notification '{"header":{}}' >/dev/null 2>&1; echo $?)" "1"
    chk es9n-not-json     "$(sim_cmd_es9_notification nope >/dev/null 2>&1; echo $?)" "1"
    chk es9n-bad-b64      "$(sim_cmd_es9_notification '{"pendingNotification":"!!"}' >/dev/null 2>&1; echo $?)" "1"
    chk es9n-no-args      "$(sim_cmd_es9_notification >/dev/null 2>&1; echo $?)" "2"

    # The four verbs are where --help lists every verb, and the ES9+ builder
    # keeps its own line and its own refusals.
    out=$(sim_cli_main --__no_such_verb__ 2>&1) || true
    chk usage-es8-build   "$(printf '%s\n' "$out" | grep -c '^  --es8-build <segment>')" "1"
    chk usage-es8-parse   "$(printf '%s\n' "$out" | grep -c '^  --es8-parse <hex>')" "1"
    chk usage-es9-resp    "$(printf '%s\n' "$out" | grep -c '^  --es9-response <op> <json>')" "1"
    chk usage-es9-notif   "$(printf '%s\n' "$out" | grep -c '^  --es9-notification <json>')" "1"
    chk usage-es9-plus    "$(printf '%s\n' "$out" | grep -c '^  --es9-plus <op> --smds')" "1"
    chk es9-plus-hnotif   "$(sim_cmd_es9_plus handleNotification --smds h >/dev/null 2>&1; echo $?)" "2"

    # ── 13. subscriber key store + AKA responder ───────────────────────
    # The store is the only place this tree holds a card secret, so the
    # assertions are about the file (mode, masking, atomic replace) and about
    # the arithmetic coming out where TS 35.208 says it should.
    local st="$STATE_DIR/sim_aka/subscribers.tsv" want got
    out=$(sim_cmd_key_add --imsi 001010123456789 \
            --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
            --op CDC202D5123E20F62B6D676AC72CB318 --sqn FF9BB4D0B607 2>&1)
    chk aka-add-stored     "$(fld "$out" stored)"      "yes"
    chk aka-add-opc        "$(fld "$out" secret2_masked)" "CD63********2BAF"
    chk aka-add-mask-ki    "$(fld "$out" ki_masked)"   "465B********A6BC"
    chk aka-add-hides-ki   "$(printf '%s\n' "$out" | grep -c '^ki	')" "0"
    chk aka-store-mode     "$(stat -c %a "$st" 2>/dev/null)" "600"
    chk aka-store-dir-mode "$(stat -c %a "$(dirname "$st")" 2>/dev/null)" "700"
    chk aka-store-opc-row  "$(awk -F'\t' '$1=="001010123456789"{print $4}' "$st")" \
                           "CD63CB71954A9F4E48A5994E37A02BAF"
    # Same IMSI again must replace the row, not append a second one.
    sim_cmd_key_add --imsi 001010123456789 --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
        --opc CD63CB71954A9F4E48A5994E37A02BAF --sqn FF9BB4D0B607 >/dev/null 2>&1
    chk aka-add-replaces    "$(sim_aka_live "$st")" "1"


    # TS 35.208 test set 1 through the responder: RAND and SQN from the
    # standard, so RES/CK/IK/AUTN are fixed values and not this tree's opinion.
    out=$(sim_cmd_aka_responder --imsi 001010123456789 \
            --rand 23553CBE9637A89D218AE64DAE47BF35 2>&1)
    chk aka-xres  "$(fld "$out" xres)" "A54211D5E3BA50BF"
    chk aka-ck    "$(fld "$out" ck)"   "B40BA9A3C58B2A05BBF0D987B21BF8CB"
    chk aka-ik    "$(fld "$out" ik)"   "F769BCD751044604127672711C6D3441"
    chk aka-autn  "$(fld "$out" autn)" "55F328B43577B9B94A9FFAC354DFAFB3"
    chk aka-mode  "$(fld "$out" mode)" "eps-aka"
    chk aka-sqn-next     "$(fld "$out" sqn_next)" "FF9BB4D0B608"
    chk aka-sqn-persist  "$(awk -F'\t' '$1=="001010123456789"{print $5}' "$st")" "FF9BB4D0B608"
    chk aka-vectors      "$(awk -F'\t' '$1=="001010123456789"{print $7}' "$st")" "1"
    # The next vector starts where the last one left off, which is the whole
    # point of keeping SQN on disk.
    out=$(sim_cmd_aka_responder --imsi 001010123456789 \
            --rand 00000000000000000000000000000000 2>&1)
    chk aka-sqn-walks-1  "$(fld "$out" sqn)"      "FF9BB4D0B608"
    chk aka-sqn-walks-2  "$(fld "$out" sqn_next)" "FF9BB4D0B609"
    chk aka-vector-2-count "$(fld "$out" vector_count)" "2"

    # The KDF is checked against OpenSSL's own HMAC rather than against a
    # second copy of this code: same S, two independent implementations.
    if command -v xxd >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
        want=$(printf '%s' '6a355c3230388d0030' | xxd -r -p |
               openssl dgst -sha256 -mac HMAC \
                   -macopt hexkey:465B5CE8B199B49FAA5F0A2EE238A6BC 2>/dev/null |
               sed 's/^.*= //')
        got=$(sim_aka_kdf 6A 465B5CE8B199B49FAA5F0A2EE238A6BC 355C3230388D)
        chk kdf-openssl-referee "$got" "${want^^}"
        chk kdf-absent-param   "$(sim_aka_kdf 6A 465B5CE8B199B49FAA5F0A2EE238A6BC '' 2>/dev/null)" ""
    else
        printf '%s\tSKIP no xxd/openssl for the KDF referee\n' "kdf-openssl-referee"
        printf '%s\tSKIP no xxd/openssl for the KDF referee\n' "kdf-absent-param"
    fi

    # 5G HE AV: with SQN pinned, KAUSF and RES* are fixed too, so the same
    # openssl referee applies to the derived keys and not just to the KDF.
    out=$(sim_cmd_aka_responder --imsi 001010123456789 \
            --rand 23553CBE9637A89D218AE64DAE47BF35 --sqn FF9BB4D0B607 \
            --5g --sn-name 5G:mnc001.mcc001.3gppnetwork.org 2>&1)
    chk fiveg-sn        "$(fld "$out" sn)"      "35473A6D6E633030312E6D63633030312E336770706E6574776F726B2E6F7267"
    chk fiveg-sn-text   "$(fld "$out" sn_text)" "5G:mnc001.mcc001.3gppnetwork.org"
    chk fiveg-kausf-len "$(printf '%s' "$(fld "$out" kausf)" | wc -c)" "64"
    chk fiveg-resstar-len "$(printf '%s' "$(fld "$out" res_star)" | wc -c)" "32"
    chk fiveg-mode      "$(fld "$out" mode)"    "5g"
    if command -v xxd >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
        # AK for that RAND/SQN, then KAUSF = HMAC(K, 6A || SN || 0100 || SQN^AK || 0030)
        local ak_raw ak v ck ik kausf_ref akey_ref
        ak_raw=$(sim_cmd_sim_auth milenage 465B5CE8B199B49FAA5F0A2EE238A6BC \
                   23553CBE9637A89D218AE64DAE47BF35 \
                   --opc CD63CB71954A9F4E48A5994E37A02BAF \
                   --sqn FF9BB4D0B607 --amf B9B9 2>/dev/null)
        ak=$(sim_kv f5 "$ak_raw"); ck=$(sim_kv ck "$ak_raw"); ik=$(sim_kv ik "$ak_raw")
        akey_ref="${ck}${ik}"
        v=$(sim_auth_xor FF9BB4D0B607 "$ak")
        # Referee: the same KDF message, keyed with CK||IK, through OpenSSL.
        kausf_ref=$(printf '%s' "6a35473A6D6E633030312E6D63633030312E336770706E6574776F726B2E6F72670100${v}0030" |
                    xxd -r -p | openssl dgst -sha256 -mac HMAC \
                        -macopt hexkey:"$akey_ref" 2>/dev/null |
                    sed 's/^.*= //')
        chk fiveg-kausf-referee "$(fld "$out" kausf)" "${kausf_ref^^}"
    else
        printf '%s\tSKIP no xxd/openssl for the KAUSF referee\n' "fiveg-kausf-referee"
    fi

    # ── refusals, by name ─────────────────────────────────────────────
    chk aka-no-imsi      "$(sim_cmd_key_add --ki 465B5CE8B199B49FAA5F0A2EE238A6BC >/dev/null 2>&1; echo $?)" "2"
    chk aka-short-ki     "$(sim_cmd_key_add --imsi 001010123456789 --ki 465B >/dev/null 2>&1; echo $?)" "2"
    chk aka-both-op      "$(sim_cmd_key_add --imsi 001010123456789 --ki 465B5CE8B199B49FAA5F0A2EE238A6BC --op CDC202D5123E20F62B6D676AC72CB318 --opc CD63CB71954A9F4E48A5994E37A02BAF >/dev/null 2>&1; echo $?)" "2"
    chk aka-top-milenage "$(sim_cmd_key_add --imsi 001010123456789 --ki 465B5CE8B199B49FAA5F0A2EE238A6BC --opc CD63CB71954A9F4E48A5994E37A02BAF --top 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF >/dev/null 2>&1; echo $?)" "2"
    chk aka-bad-sqn      "$(sim_cmd_key_add --imsi 001010123456789 --ki 465B5CE8B199B49FAA5F0A2EE238A6BC --opc CD63CB71954A9F4E48A5994E37A02BAF --sqn 1234 >/dev/null 2>&1; echo $?)" "2"
    chk aka-unknown-imsi "$(sim_cmd_aka_responder --imsi 999999999999999 >/dev/null 2>&1; echo $?)" "1"
    chk aka-bad-rand     "$(sim_cmd_aka_responder --imsi 001010123456789 --rand 00 >/dev/null 2>&1; echo $?)" "2"
    chk aka-5g-no-sn     "$(sim_cmd_aka_responder --imsi 001010123456789 --5g >/dev/null 2>&1; echo $?)" "2"
    chk aka-sn-without-5g "$(sim_cmd_aka_responder --imsi 001010123456789 --sn 355C >/dev/null 2>&1; echo $?)" "2"
    chk aka-both-sn      "$(sim_cmd_aka_responder --imsi 001010123456789 --5g --sn 355C --sn-name x >/dev/null 2>&1; echo $?)" "2"
    chk aka-sn-odd       "$(sim_cmd_aka_responder --imsi 001010123456789 --5g --sn 355 >/dev/null 2>&1; echo $?)" "2"
    chk aka-key-show-missing "$(sim_cmd_key_show --imsi 000000000000001 >/dev/null 2>&1; echo $?)" "1"

    # ── masking and reveal ────────────────────────────────────────────
    chk aka-list-no-secret "$(sim_cmd_key_list | grep -c '465B5CE8B199B49FAA5F0A2EE238A6BC')" "0"
    chk aka-list-masked    "$(sim_cmd_key_list | grep -c '465B\*\*\*\*\*\*\*\*A6BC')" "1"
    chk aka-show-reveal    "$(sim_cmd_key_show --imsi 001010123456789 --reveal |
                               grep -c '465B5CE8B199B49FAA5F0A2EE238A6BC')" "1"

    # ── resident responder ────────────────────────────────────────────
    out=$(printf 'VECTOR 001010123456789 00112233445566778899AABBCCDDEEFF\nVECTOR 999999999999999\nBOGUS\nQUIT\n' |
          sim_cmd_aka_serve 2>&1)
    chk serve-ready    "$(printf '%s\n' "$out" | grep -c '^serve	ready')" "1"
    chk serve-served   "$(fld "$out" served)"   "1"
    chk serve-rejected "$(fld "$out" rejected)" "2"
    chk serve-requests "$(fld "$out" requests)" "4"
    chk serve-vector   "$(printf '%s\n' "$out" | grep -c '^result	ok')" "1"
    # Served vectors keep walking SQN across requests, on disk.
    chk serve-sqn-store "$(awk -F'\t' '$1=="001010123456789"{print $5}' "$st")" "FF9BB4D0B609"
    chk serve-vector-count "$(awk -F'\t' '$1=="001010123456789"{print $7}' "$st")" "4"

    # ── removal ──────────────────────────────────────────────────────
    chk aka-remove-rc   "$(sim_cmd_key_remove --imsi 001010123456789 >/dev/null 2>&1; echo $?)" "0"
    chk aka-remove-gone "$(sim_aka_live "$st")" "0"
    chk aka-remove-again "$(sim_cmd_key_remove --imsi 001010123456789 >/dev/null 2>&1; echo $?)" "1"

    # The verbs have to be in the usage text, because that is where the index
    # and the GUI drawer read them from.
    out=$(sim_cli_main --__no_such_verb__ 2>&1) || true
    chk usage-key-add    "$(printf '%s\n' "$out" | grep -c '^  --key-add ')" "1"
    chk usage-key-list   "$(printf '%s\n' "$out" | grep -c '^  --key-list ')" "1"
    chk usage-aka-resp   "$(printf '%s\n' "$out" | grep -c '^  --aka-responder ')" "1"
    chk usage-aka-serve  "$(printf '%s\n' "$out" | grep -c '^  --aka-serve ')" "1"

    # ── profile state machine (R12) ────────────────────────────────────
    # Four sequences: the legal one, a delete while enabled, the one-slot
    # rule when a second profile is enabled, and an enable after a delete.
    local legal illegal oneslot afterdelete
    legal=$(printf 'install 89440000000000000001\nenable 89440000000000000001\ndisable 89440000000000000001\ndelete 89440000000000000001\n' \
        | sim_profile_model - 2>&1)
    chk prof-legal-refused "$(printf '%s\n' "$legal" | awk -F'\t' '$1=="refused"{print $2; exit}')" "0"
    chk prof-legal-final   "$(printf '%s\n' "$legal" | grep -c '^final.89440000000000000001	deleted$')" "1"
    illegal=$(printf 'install 89440000000000000001\nenable 89440000000000000001\ndelete 89440000000000000001\n' \
        | sim_profile_model - 2>&1)
    chk prof-delete-enabled "$(printf '%s\n' "$illegal" | awk -F'\t' '$1=="event.3.verdict"{print $2; exit}')" "refused"
    chk prof-delete-rule    "$(printf '%s\n' "$illegal" | grep -c 'disabled before it is deleted')" "1"
    chk prof-illegal-rc     "$(printf 'install 89440000000000000001\nenable 89440000000000000001\ndelete 89440000000000000001\n' \
        | sim_profile_model - >/dev/null 2>&1; echo $?)" "1"
    oneslot=$(printf 'install 89440000000000000001\ninstall 89440000000000000002\nenable 89440000000000000001\nenable 89440000000000000002\n' \
        | sim_profile_model - 2>&1)
    chk prof-oneslot-side   "$(printf '%s\n' "$oneslot" | awk -F'\t' '$1=="event.4.side"{print $2; exit}')" "89440000000000000001"
    chk prof-oneslot-count  "$(printf '%s\n' "$oneslot" | grep -c '^final\.')" "2"
    chk prof-oneslot-refused "$(printf '%s\n' "$oneslot" | awk -F'\t' '$1=="refused"{print $2; exit}')" "0"
    afterdelete=$(printf 'install 89440000000000000001\ndelete 89440000000000000001\nenable 89440000000000000001\n' \
        | sim_profile_model - 2>&1)
    chk prof-deleted-enable "$(printf '%s\n' "$afterdelete" | awk -F'\t' '$1=="event.3.verdict"{print $2; exit}')" "refused"
    chk prof-delete-disabled "$(printf '%s\n' "$afterdelete" | awk -F'\t' '$1=="event.2.verdict"{print $2; exit}')" "ok"
    chk prof-no-file "$(sim_profile_model /nonexistent/events.tsv >/dev/null 2>&1; echo $?)" "1"
    chk prof-no-args "$(sim_profile_model >/dev/null 2>&1; echo $?)" "2"
    chk prof-bad-op  "$(printf 'frobnicate 8944\n' | sim_profile_model - >/dev/null 2>&1; echo $?)" "1"
    chk prof-bad-iccid "$(printf 'install 1234\n' | sim_profile_model - >/dev/null 2>&1; echo $?)" "1"

    # ── RSP binding audit (R10) ────────────────────────────────────────
    # SGP.22's protection is binding, not secrecy: the transactionId ties a
    # response to its request, the SM-DP+ signature ties the command to its
    # key, and the EID ties the profile to one device. The audit says which
    # tie is missing, so a replay is a finding rather than a hope.
    local rsp_ok rsp_replay rsp_unsigned
    rsp_ok='{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"AB12","serverSigned1":"MAA=","serverSignature1":"MAA=","euiccCiPKIdToBeUsed":"MAA=","serverCertificate":"MAA="}'
    chk rsp-bound "$(sim_cli_main --rsp-audit "$rsp_ok" --request '{"transactionId":"AB12"}' 2>/dev/null | awk -F'\t' '$1=="findings"{print $2}')" "0"
    chk rsp-bound-rc "$(sim_cli_main --rsp-audit "$rsp_ok" --request '{"transactionId":"AB12"}' >/dev/null 2>&1; echo $?)" "0"
    rsp_replay=$(sim_cli_main --rsp-audit "$rsp_ok" --request '{"transactionId":"CD34"}' 2>&1)
    chk rsp-replay-sev "$(printf '%s\n' "$rsp_replay" | awk -F'\t' '$1=="finding.1"{print $2; exit}')" "HIGH"
    chk rsp-replay-rc  "$(sim_cli_main --rsp-audit "$rsp_ok" --request '{"transactionId":"CD34"}' >/dev/null 2>&1; echo $?)" "1"
    rsp_unsigned=$(sim_cli_main --rsp-audit '{"transactionId":"AB12"}' 2>&1)
    chk rsp-unsigned-sev "$(printf '%s\n' "$rsp_unsigned" | awk -F'\t' '$1=="finding.1"{print $2; exit}')" "MEDIUM"
    chk rsp-unsigned-op  "$(printf '%s\n' "$rsp_unsigned" | awk -F'\t' '$1=="operation"{print $2; exit}')" "undetermined"
    # A named EID that is not the supplied one is the moved-profile case.
    chk rsp-eid-mismatch "$(sim_cli_main --rsp-audit '{"transactionId":"AB12","eidValue":"AABB"}' --eid CCDD 2>/dev/null | grep -c '^finding\.[0-9]*	HIGH	.*EID')" "1"
    chk rsp-bad-json "$(sim_cli_main --rsp-audit 'nope' >/dev/null 2>&1; echo $?)" "1"
    chk rsp-no-args  "$(sim_cli_main --rsp-audit >/dev/null 2>&1; echo $?)" "2"
    # The plans name what each attack needs, and refuse an unknown one.
    chk rsp-plan-profile "$(sim_cli_main --rsp-plan profile-move 2>/dev/null | awk -F'\t' '$1=="status"{print $2; exit}')" "handoff"
    chk rsp-plan-notify  "$(sim_cli_main --rsp-plan notification-spoof 2>/dev/null | grep -c '^what	')" "1"
    chk rsp-plan-refused "$(sim_cli_main --rsp-plan nope >/dev/null 2>&1; echo $?)" "2"

    # ── SCP03t: the derivation, and a card's cryptogram (R11) ──────────
    # The keys SGP.02 2.6.4 rides on: S-ENC/S-MAC/S-RMAC from the Annex D
    # counter-mode KDF, then the card and host cryptograms over S-MAC.
    local scp_enc=000102030405060708090A0B0C0D0E0F
    local scp_mac=101112131415161718191A1B1C1D1E1F
    local scp; scp=$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF 2>&1)
    chk scp-s-enc  "$(fld "$scp" s_enc)"  "1771157962A029C5435A1AC81D0B9806"
    chk scp-s-mac  "$(fld "$scp" s_mac)"  "3E994A1F2EAF7182282B2E5ED3870B83"
    chk scp-s-rmac "$(fld "$scp" s_rmac)" "49214B50BD45D69A2FEB47C69DE5407E"
    chk scp-card-c "$(fld "$scp" card_cryptogram)" "D71A889EFCF709E8"
    chk scp-host-c "$(fld "$scp" host_cryptogram)" "75A94E14D36602F1"
    # A card's cryptogram checked against what the derivation predicts: this
    # is the verification, and a mismatch has to fail rather than print.
    local scp_ok; scp_ok=$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
        --card-cryptogram D71A889EFCF709E8 2>&1)
    chk scp-verify-yes "$(fld "$scp_ok" card_cryptogram_matches)" "yes"
    chk scp-verify-rc  "$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
        --card-cryptogram D71A889EFCF709E8 >/dev/null 2>&1; echo $?)" "0"
    chk scp-verify-no-rc "$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
        --card-cryptogram 0000000000000000 >/dev/null 2>&1; echo $?)" "1"
    chk scp-verify-no "$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
        --card-cryptogram 0000000000000000 2>/dev/null | awk -F'\t' '$1=="card_cryptogram_matches"{print $2}')" "no"
    chk scp-verify-short "$(sim_cli_main --es8-scp03t --k-enc "$scp_enc" --k-mac "$scp_mac" \
        --host-challenge 0011223344556677 --card-challenge 8899AABBCCDDEEFF \
        --card-cryptogram 0011 >/dev/null 2>&1; echo $?)" "1"
    # The outside implementation agrees with every value above, or the check
    # says SKIP rather than pretending.
    if command -v openssl >/dev/null 2>&1; then
        chk scp-openssl "$(bash "$IMSISTING_ROOT/tools/check-scp03t.sh" 2>/dev/null | grep -c '^RESULT	PASS')" "1"
    else
        chk scp-openssl "skip" "skip"
    fi

    # ── the card side (R7) ─────────────────────────────────────────────    # ── the card side (R7) ─────────────────────────────────────────────
    # A UE emulator's own conversation: SELECT the USIM application, read
    # EF_IMSI, authenticate with the TS 35.208 set-1 vector. The R-APDU is the
    # answer a handset would take off the wire, so it is asserted whole.
    # The store is re-seeded here because the removal test above emptied it.
    sim_cmd_key_add --imsi 001010123456789 \
        --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
        --opc CD63CB71954A9F4E48A5994E37A02BAF --sqn FF9BB4D0B607 >/dev/null 2>&1
    chk bcd-imsi "$(sim_bcd_encode 001010123456789)" "00010121436587F9"
    chk bcd-imsi-3mnc "$(sim_bcd_encode 310150123456789)" \
        "$(bash "$IMSISTING_ROOT/modules/09_lte_attach.sh" --imsi-encode 310150123456789 \
            | awk -F'\t' '$1=="bcd"{print $2; exit}')"
    chk usim-ef-imsi "$(sim_usim_ef_imsi 001010123456789)" "0800010121436587F9"

    local usim_in usim_out
    usim_in=$(printf '00A4040009A0000000871002FF86\n00A4000C026F07\n00B000000A\n')
    usim_out=$(printf '%s' "$usim_in" | sim_usim_serve --imsi 001010123456789 2>&1)
    chk usim-serve-ready "$(fld "$usim_out" responder)" "usim"
    chk usim-select-aid  "$(printf '%s\n' "$usim_out" | awk -F'\t' '$1=="sw"{n++; if(n==1) print $2}')" "9000"
    chk usim-select-ef   "$(printf '%s\n' "$usim_out" | awk -F'\t' '$1=="selected"{print $2; exit}')" "6F07"
    chk usim-read-imsi   "$(printf '%s\n' "$usim_out" | awk -F'\t' '$1=="response"{n++; if(n==3) print $2}')" "0800010121436587F9"
    chk usim-rapdu       "$(printf '%s\n' "$usim_out" | awk -F'\t' '$1=="rapdu"{n++; if(n==3) print $2}')" "0800010121436587F99000"
        "0800010121436587F99000"
    chk usim-sent        "$(fld "$usim_out" sent)" "0"

    # AUTHENTICATE, 3G: RES(8) || CK || IK, and the SQN counter moves.
    local sqn_before sqn_after usim_auth
    sqn_before=$(sim_kv sqn "$(sim_cmd_aka_responder --imsi 001010123456789 --rand 00000000000000000000000000000000 --no-persist 2>/dev/null)")
    # The AUTN's SQN must be *ahead* of the card's for a vector: the card
    # answers a stale network with 9862 + AUTS (asserted further down).
    usim_auth=$(printf '00888100 20 %s %s%s\n' 23553CBE9637A89D218AE64DAE47BF35 \
        "$(sim_auth_xor FF9BB4D0B608 AA689C648370)" 00000000000000000000 \
        | tr -d ' ' | sim_usim_serve --imsi 001010123456789 2>&1)
    chk usim-auth-sw    "$(printf '%s\n' "$usim_auth" | awk -F'\t' '$1=="sw"{print $2; exit}')" "9000"
    chk usim-auth-vec   "$(printf '%s\n' "$usim_auth" | awk -F'\t' '$1=="response"{print $2; exit}')" \
        "A54211D5E3BA50BFB40BA9A3C58B2A05BBF0D987B21BF8CBF769BCD751044604127672711C6D3441"
    sqn_after=$(sim_aka_row 001010123456789 | cut -f5)
    chk usim-auth-sqn   "$(( 16#$sqn_after > 16#$sqn_before ? 1 : 0 ))" "1"
    # The refusals a card gives, and the one it names instead of guessing.
    chk usim-no-imsi    "$(sim_usim_serve </dev/null >/dev/null 2>&1; echo $?)" "2"
    chk usim-2g-refused "$(printf '0088010020%s\n' 23553CBE9637A89D218AE64DAE47BF3500000000000000000000000000000000 | \
        sim_usim_serve --imsi 001010123456789 2>/dev/null | awk -F'\t' '$1=="sw"{print $2; exit}')" "6A86"
    chk usim-unknown-file "$(printf '00A4000C026F38\n' | sim_usim_serve --imsi 001010123456789 2>/dev/null | \
        awk -F'\t' '$1=="sw"{print $2; exit}')" "6A82"
    chk usim-unknown-ins "$(printf '00F0000000\n' | sim_usim_serve --imsi 001010123456789 2>/dev/null | \
        awk -F'\t' '$1=="sw"{print $2; exit}')" "6D00"
    chk usim-sm-refused "$(printf '8CA4000002\n' | sim_usim_serve --imsi 001010123456789 2>/dev/null | \
        awk -F'\t' '$1=="sw"{print $2; exit}')" "6E00"
    chk usim-read-no-ef "$(printf '00B0000002\n' | sim_usim_serve --imsi 001010123456789 2>/dev/null | \
        awk -F'\t' '$1=="sw"{print $2; exit}')" "6986"
    # --usim-tcp opens a real listener, so the test only exercises its
    # refusals: a bad port and a missing IMSI both answer 2, and the socat
    # dependency is asserted without starting a socket that would hang the run.
    chk usim-tcp-bad-port "$(sim_cmd_usim_tcp 0 --imsi 001010123456789 >/dev/null 2>&1; echo $?)" "2"
    chk usim-tcp-no-imsi  "$(sim_cmd_usim_tcp 2626 >/dev/null 2>&1; echo $?)" "2"

    # ── AUTS: the resync a stale SQN needs (R8) ────────────────────────
    # TS 35.208 set 1: AUTS = (SQN_MS xor AK) || MAC-S with AMF=0000 on f1*.
    local auts_row auts_hex
    auts_row=$(sim_auts_build 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 FF9BB4D0B607)
    chk auts-ak    "$(fld "$auts_row" ak)"    "AA689C648370"
    chk auts-macs  "$(fld "$auts_row" mac_s)" "CF44E93596E355C6"
    chk auts-hex   "$(fld "$auts_row" auts)"  "55F328B43577CF44E93596E355C6"
    chk auts-octets "$(fld "$auts_row" octets)" "14"

    local ver; ver=$(sim_auts_verify 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 \
        "$(fld "$auts_row" auts)")
    chk auts-verify-verdict "$(fld "$ver" verdict)" "valid"
    chk auts-verify-sqn     "$(fld "$ver" sqn_ms)"  "FF9BB4D0B607"
    chk auts-verify-next    "$(fld "$ver" next_sqn_hex)" "FF9BB4D0B608"
    # A one-nibble change in MAC-S must fail: that is what makes it a check.
    chk auts-verify-tamper "$(sim_auts_verify 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 \
        55F328B43577CF44E93596E355C7 2>/dev/null | awk -F'\t' '$1=="verdict"{print $2}')" "invalid"
    chk auts-verify-tamper-rc "$(sim_auts_verify 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 \
        55F328B43577CF44E93596E355C7 >/dev/null 2>&1; echo $?)" "1"
    chk auts-short "$(sim_auts_build 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF 23553CBE9637A89D218AE64DAE47BF35 FF9F >/dev/null 2>&1; echo $?)" "2"

    # The card answers a network that is *behind* with 9862 + AUTS, and a
    # network that is ahead with a vector. Both are the same APDU.
    local rand_h="23553CBE9637A89D218AE64DAE47BF35"
    local stale_ahead ahead_auth behind_auth
    stale_ahead="AA689C648370"   # AK for this RAND
    # AUTN with SQN FF9BB4D0B607 xor AK (equal to the card's SQN) -> not ahead.
    ahead_auth=$(printf '00888100 20 %s %s00000000000000000000\n' "$rand_h" \
        "$(sim_auth_xor FF9BB4D0B607 AA689C648370)" | tr -d ' ' | sim_usim_serve --imsi 001010123456789 2>&1)
    chk usim-stale-sw    "$(printf '%s\n' "$ahead_auth" | awk -F'\t' '$1=="sw"{print $2; exit}')" "9862"
    # The card's AUTS names the card's *current* SQN, so the assertion is the
    # pair (verifies, and recovers the store's own counter) rather than a byte
    # string that would drift every time the store moves.
    local stale_auts stale_ver
    stale_auts=$(printf '%s\n' "$ahead_auth" | awk -F'\t' '$1=="response"{print $2; exit}')
    stale_ver=$(sim_auts_verify 465B5CE8B199B49FAA5F0A2EE238A6BC \
        CD63CB71954A9F4E48A5994E37A02BAF "$rand_h" "$stale_auts")
    chk usim-stale-auts  "$(printf '%s\n' "$stale_ver" | awk -F'\t' '$1=="verdict"{print $2; exit}')" "valid"
    chk usim-stale-sqn   "$(printf '%s\n' "$stale_ver" | awk -F'\t' '$1=="sqn_ms"{print $2; exit}')" \
        "$(sim_aka_row 001010123456789 | cut -f5)"
    # Now a network one step ahead of the card *as it stands now* -- the
    # earlier authenticate moved the store's SQN -- so the card computes a
    # vector rather than resynchronising.
    local sqn_now sqn_ahead
    sqn_now=$(sim_aka_row 001010123456789 | cut -f5)
    sqn_ahead=$(printf '%012X' "$(( 16#$sqn_now + 1 ))")
    behind_auth=$(printf '00888100 20 %s %s00000000000000000000\n' "$rand_h" \
        "$(sim_auth_xor "$sqn_ahead" AA689C648370)" | tr -d ' ' | sim_usim_serve --imsi 001010123456789 2>&1)
    chk usim-ahead-sw    "$(printf '%s\n' "$behind_auth" | awk -F'\t' '$1=="sw"{print $2; exit}')" "9000"


    printf 'ASSERTIONS\t%d\n' "$n_checks"
    rm -rf "$d"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
sim_menu() {
    local c p
    while true; do
        banner
        echo -e "  ${C_MAG}=== SIM / eSIM / OTA Attacks ===${C_RESET}"
        echo -e "  reader: ${C_GRN}$(sim_find_reader || echo none)${C_RESET}"
        echo -e "  apdus:  ${C_GRN}$(sim_log_count)${C_RESET}"
        echo -e "  loot:   ${C_DIM}$SIM_DIR${C_RESET}\n"
        cat << 'M'
  [1]  select an EF and show the APDU
  [2]  read binary / read record APDU builder
  [3]  parse a command or response APDU (SW decode)
  [4]  decode ICCID from a record hex
  [5]  decode IMSI from a record hex
  [6]  decode EF_AD (PIN/PUK/ADM state)
  [7]  parse an OTA SMS TPDU (TAR / SPI / KIc / KID / CNTR)
  [8]  SPI bit-field decode
  [9]  eSIM RSP roles and profile states
  [a]  plan: OTA replay        (handoff)
  [b]  plan: S@T / WIB browser (handoff)
  [c]  plan: eSIM download     (handoff)
  [d]  plan: live APDU over PC/SC (handoff)
  [e]  list the known USIM file ids
  [f]  show the APDU log
  [g]  DPA model: COMP128-1 leakage point for a KI + RAND
  [h]  DPA model: synthetic-trace key recovery (verified)
  [i]  plan: DPA capture rig   (handoff)
  [j]  DPA model: noise / trace-count / model-mismatch sweeps
  [k]  SIM auth vector: COMP128-1/2/3, Milenage or TUAK
  [l]  SGP.22 ES9+ request builder (nothing is sent)
  [m]  SGP.22 ES8+ TLV builder (BPP segments)
  [n]  walk a Bound Profile Package TLV by TLV
  [o]  parse an ES9+ response body
  [p]  parse an ES9+ HandleNotification (6.5.2.9)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  file id (hex, e.g. 6F07)> " p
               sim_cmd_select "$p" | column -t -s$'\t' 2>/dev/null || sim_cmd_select "$p"
               read -rp "  press enter " _ ;;
            2) read -rp "  (b)inary or (r)ecord> " p
               if [[ "$p" == b* ]]; then
                   read -rp "  offset> " o; read -rp "  Le> " l
                   sim_cmd_read_binary "$o" "$l" | column -t -s$'\t'
               else
                   read -rp "  record number> " r; read -rp "  Le> " l
                   sim_cmd_read_record "$r" 04 "$l" | column -t -s$'\t'
               fi
               read -rp "  press enter " _ ;;
            3) read -rp "  hex> " p
               sim_cmd_parse_apdu "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            4) read -rp "  ICCID record hex> " p
               sim_cmd_decode_iccid "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            5) read -rp "  IMSI record hex> " p
               sim_cmd_decode_imsi "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            6) read -rp "  EF_AD hex> " p
               sim_cmd_decode_ad "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            7) read -rp "  TPDU hex> " p
               sim_cmd_parse_ota "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            8) read -rp "  SPI (decimal)> " p
               sim_spi_decode "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            9) sim_rsp_roles; echo; sim_profile_state_table | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            a) sim_plan ota-replay;      read -rp "  press enter " _ ;;
            b) sim_plan sat-wib;         read -rp "  press enter " _ ;;
            c) sim_plan esim-download;   read -rp "  press enter " _ ;;
            d) sim_plan apdu-live;       read -rp "  press enter " _ ;;
            e) echo
               for f in 3F00 7F20 2FE2 6F07 6F20 6FAD 6F7E 6F08 6F46 6F73 6F7F 6F98 6FB5; do
                   printf '  %s  %s\n' "$f" "$(sim_file_name "$f" | cut -d'|' -f1)"
               done
               read -rp "  press enter " _ ;;
            f) [[ -f "$SIM_APDU_LOG" ]] && column -t -s$'\t' < "$SIM_APDU_LOG" || warn "no APDU log yet"
               read -rp "  press enter " _ ;;
            g) read -rp "  KI (32 hex)> " p; read -rp "  RAND (32 hex)> " q
               sim_dpa_model "$p" "$q" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            h) read -rp "  KI (32 hex)> " p
               read -rp "  traces [256]> " q; read -rp "  sigma [1.0]> " s
               sim_dpa_sim "$p" "${q:-256}" "${s:-1.0}" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            i) sim_plan dpa-lab;         read -rp "  press enter " _ ;;
            j) read -rp "  KI (32 hex)> " p
               sim_dpa_sweep "$p" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            k) read -rp "  algo [comp128-1|comp128-2|comp128-3|milenage|tuak]> " p
               read -rp "  KI (32 hex; 64 hex for tuak-256)> " q
               read -rp "  RAND (32 hex)> " r
               if [[ "$p" == milenage ]]; then
                   read -rp "  OP or OPc (32 hex)> " s
                   sim_cmd_sim_auth milenage "$q" "$r" --op "$s" | column -t -s$'\t'
               elif [[ "$p" == tuak ]]; then
                   read -rp "  TOP (64 hex)> " s
                   sim_cmd_sim_auth tuak "$q" "$r" --top "$s" | column -t -s$'\t'
               else
                   sim_cmd_sim_auth "$p" "$q" "$r" | column -t -s$'\t'
               fi
               read -rp "  press enter " _ ;;
            l) read -rp "  SM-DP+ host[:port]> " p
               read -rp "  eUICC challenge (32 hex)> " q
               read -rp "  EUICCInfo1 (DER hex)> " r
               sim_cmd_es9_plus initiateAuthentication --smds "$p" \
                   --euicc-challenge "$q" --euicc-info1 "$r" | column -t -s$'\t'
               read -rp "  press enter " _ ;;
            m) read -rp "  segment [bpp-header|configure-isdp|store-metadata|replace-session-keys|bpp]> " p
               sim_cmd_es8_build "$p" | column -t -s$'\t' 2>/dev/null || sim_cmd_es8_build "$p"
               read -rp "  press enter " _ ;;
            n) read -rp "  BPP hex> " p
               sim_cmd_es8_parse "$p" | column -t -s$'\t' 2>/dev/null || sim_cmd_es8_parse "$p"
               read -rp "  press enter " _ ;;
            o) read -rp "  op [initiateAuthentication|authenticateClient|getBoundProfilePackage|cancelSession]> " p
               read -rp "  response JSON> " q
               sim_cmd_es9_response "$p" "$q" | column -t -s$'\t' 2>/dev/null || sim_cmd_es9_response "$p" "$q"
               read -rp "  press enter " _ ;;
            p) read -rp "  HandleNotification JSON> " p
               sim_cmd_es9_notification "$p" | column -t -s$'\t' 2>/dev/null || sim_cmd_es9_notification "$p"
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── subscriber key store + AKA responder ────────────────────────────────
# The 3GPP secret K (and OPC/TOP) has to live somewhere between runs. This is
# that somewhere: one TSV row per subscriber under STATE_DIR, mode 0600, and a
# responder that walks SQN the way a USIM does — one increment per vector,
# persisted, so a replay of the previous vector is refused by the network's own
# freshness check rather than by a flag in this tree.
#
# Columns (tab separated, one header line beginning with #):
#   imsi  ki  algo  secret2  sqn  amf  vectors  updated
# algo is milenage or tuak; secret2 is OPC for milenage and TOP for tuak, so
# every vector is one call to tools/gsm_crypto.py with no second lookup.
#
# WHAT IS REAL: the quintet (or the 5G HE AV inputs), the KDF calls, the SQN
# counter, and the file. WHAT IS NOT: no card is touched, no USIM is emulated,
# and the AUTS/resynchronisation path is not built here (it needs SQN_MS, which
# only the peer in a resync message can supply).

SIM_AKA_HEADER='# imsi	ki	algo	secret2	sqn	amf	vectors	updated'
SIM_AKA_COLS=8

sim_aka_dir()   { printf '%s/sim_aka' "${STATE_DIR:-$IMSISTING_ROOT/state}"; }
sim_aka_store() { printf '%s/subscribers.tsv' "$(sim_aka_dir)"; }

sim_aka_usage() {
    printf 'ERROR\tusage: --key-add --imsi <digits> --ki <32hex> (--opc <32hex>|--op <32hex>|--top <64hex>) [--algo milenage|tuak] [--sqn <12hex>] [--amf <4hex>]\n' >&2
    printf 'ERROR\t       --key-list [--reveal] | --key-show --imsi <digits> [--reveal] | --key-remove --imsi <digits>\n' >&2
    printf 'ERROR\t       --aka-responder --imsi <digits> [--rand <32hex>] [--sqn <12hex>] [--5g --sn <hex>|--sn-name <text>]\n' >&2
    printf 'ERROR\t       --aka-serve [--5g --sn <hex>|--sn-name <text>]\n' >&2
}

# Create the directory and the file if they are missing; print the path.
sim_aka_ensure() {
    local d f
    d=$(sim_aka_dir)
    f=$(sim_aka_store)
    if [[ ! -d "$d" ]]; then
        mkdir -p "$d" 2>/dev/null || {
            printf 'ERROR\tcannot create %s\n' "$(sim_sanitize "$d")" >&2; return 1; }
        chmod 700 "$d" 2>/dev/null
    fi
    if [[ ! -f "$f" ]]; then
        # umask, not a later chmod, so the secrets are never briefly world-readable.
        ( umask 077; printf '%s\n' "$SIM_AKA_HEADER" > "$f" ) || {
            printf 'ERROR\tcannot write %s\n' "$(sim_sanitize "$f")" >&2; return 1; }
    fi
    chmod 600 "$f" 2>/dev/null
    printf '%s' "$f"
}

sim_aka_mask() { # <hex> -> first 4 and last 4, middle starred
    local h="${1:-}"
    if (( ${#h} <= 8 )); then printf '********'; return 0; fi
    printf '%s********%s' "${h:0:4}" "${h: -4}"
}

sim_aka_live() { # <store> -> number of subscriber rows
    [[ -f "${1:-}" ]] || { printf 0; return 0; }
    awk -F'\t' '!/^#/ && $1 != "" { n++ } END { printf "%d", n + 0 }' "$1"
}

sim_aka_row() { # <imsi> -> that subscriber's row, or empty
    local f
    f=$(sim_aka_store)
    [[ -f "$f" ]] || return 0
    awk -F'\t' -v i="$1" '!/^#/ && $1 == i { print; exit }' "$f"
}

# Replace or append one row. Atomic: awk writes a sibling temp file, then mv.
sim_aka_put() { # <imsi> <ki> <algo> <secret2> <sqn> <amf> <vectors>
    local d f tmp row
    d=$(sim_aka_dir)
    f=$(sim_aka_store)
    tmp="$f.tmp.$$"
    mkdir -p "$d" 2>/dev/null || return 1
    [[ -f "$f" ]] || printf '%s\n' "$SIM_AKA_HEADER" > "$f" || return 1
    row=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
    if awk -F'\t' -v OFS='\t' -v i="$1" -v r="$row" '
            /^#/ { print; next }
            $1 == i { print r; seen = 1; next }
            { print }
            END { if (!seen) print r }' "$f" > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$f" 2>/dev/null && chmod 600 "$f" 2>/dev/null && return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

sim_aka_del() { # <imsi> -> 0 removed, 1 absent
    local f tmp hit
    f=$(sim_aka_store)
    tmp="$f.tmp.$$"
    [[ -f "$f" ]] || return 1
    hit=$(awk -F'\t' -v i="$1" '!/^#/ && $1 == i { n++ } END { printf "%d", n + 0 }' "$f")
    (( hit )) || return 1
    if awk -F'\t' -v i="$1" '/^#/ || $1 != i { print }' "$f" > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$f" 2>/dev/null && chmod 600 "$f" 2>/dev/null && return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

# Run a command under an exclusive lock on the store. Without flock the work
# still happens: the store is small, and a lost update is visible as a stuck
# SQN rather than as a silently wrong vector.
sim_aka_locked() {
    local d l
    d=$(sim_aka_dir)
    if ! mkdir -p "$d" 2>/dev/null; then "$@"; return $?; fi
    l="$d/.lock"
    if command -v flock >/dev/null 2>&1; then
        ( flock -x 9 2>/dev/null; "$@" ) 9>>"$l"
        return $?
    fi
    "$@"
}

sim_aka_sqn_inc() { # <12 hex> -> next SQN, modulo 2^48
    local v
    v=$(( ( 16#${1:-0} + 1 ) & 0xFFFFFFFFFFFF ))
    printf '%012X' "$v"
}

sim_aka_rand() { # 16 random bytes, uppercase hex
    local r=''
    if [[ -r /dev/urandom ]]; then
        r=$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')
    fi
    if (( ${#r} != 32 )); then
        printf 'ERROR\tno /dev/urandom on this host; pass --rand\n' >&2
        return 1
    fi
    printf '%s' "${r^^}"
}

sim_aka_text_hex() { # <text> -> its UTF-8 bytes as hex (the SN name is text on the wire)
    printf '%s' "$1" | od -An -tx1 -v 2>/dev/null | tr -d ' \n' | tr 'a-f' 'A-F'
}

sim_aka_kdf() { # <fc> <key-hex> <p0-hex> [p1] [p2] -> the KDF output hex
    local fc="$1" key="$2" p0="$3" p1="${4:-}" p2="${5:-}" tool out
    tool="$IMSISTING_ROOT/tools/gsm_crypto.py"
    [[ -f "$tool" ]] || { printf 'ERROR\tno %s\n' "$tool" >&2; return 1; }
    local -a args=(--kdf "$fc" --key "$key" --p0 "$p0")
    [[ -n "$p1" ]] && args+=(--p1 "$p1")
    [[ -n "$p2" ]] && args+=(--p2 "$p2")
    out=$(python3 "$tool" "${args[@]}" 2>/dev/null) || return 1
    printf '%s' "$(sim_kv out "$out")"
}

# A named 5G derivation. The truncation (RES* is the rightmost 128 of 256
# bits) and the key (CK||IK) live in the tool, not here, so the shell never
# re-derives a clause from memory.
sim_aka_derive() { # <res-star|kausf|hxres> [k=v ...] -> one value
    local kind="$1"; shift
    local tool out err rc=0
    tool="$IMSISTING_ROOT/tools/gsm_crypto.py"
    [[ -f "$tool" ]] || { printf 'ERROR\tno %s\n' "$tool" >&2; return 1; }
    err=$(mktemp "${MOD_TMP:-/tmp}/derive.XXXXXX" 2>/dev/null) || err=/tmp/derive.$$
    out=$(python3 "$tool" --derive "$kind" "$@" 2>"$err") || rc=$?
    if (( rc != 0 )); then
        [[ -s "$err" ]] && sed -n '1p' "$err" >&2
        rm -f "$err"
        return 1
    fi
    rm -f "$err"
    case "$kind" in
        res-star) awk -F'\t' '$1=="res_star"{print $2; exit}' <<< "$out" ;;
        kausf)    awk -F'\t' '$1=="kausf"{print $2; exit}' <<< "$out" ;;
        hxres)    awk -F'\t' '$1=="hxres_star"{print $2; exit}' <<< "$out" ;;
        *)        return 1 ;;
    esac
}

# Resolve --sn / --sn-name into UTF-8 bytes as hex. Both spell the same thing;
# the standard writes the SN name as text ('5G:mnc001.mcc001.3gppnetwork.org'),
# and the KDF takes its bytes, so the text is hex-encoded here once.
sim_aka_sn_hex() { # <sn-hex> <sn-name> -> hex, or empty
    local sn="${1:-}" name="${2:-}"
    if [[ -n "$sn" && -n "$name" ]]; then
        printf 'ERROR\tgive --sn or --sn-name, not both\n' >&2
        return 2
    fi
    if [[ -n "$sn" ]]; then
        sn="${sn^^}"
        [[ "$sn" =~ ^[0-9A-F]+$ && $(( ${#sn} % 2 )) -eq 0 ]] || {
            printf 'ERROR\t--sn must be an even number of hex digits\n' >&2; return 2; }
        printf '%s' "$sn"
        return 0
    fi
    if [[ -n "$name" ]]; then
        local h
        h=$(sim_aka_text_hex "$name")
        [[ -n "$h" ]] || { printf 'ERROR\t--sn-name produced no bytes\n' >&2; return 2; }
        printf '%s' "$h"
        return 0
    fi
    return 1
}

# ── --key-add ────────────────────────────────────────────────────────────
sim_cmd_key_add() {
    local imsi='' ki='' opc='' op='' top='' algo='milenage' sqn='' amf='B9B9' reveal=0
    while (( $# )); do
        case "$1" in
            --imsi)   imsi="${2:-}";   shift 2 2>/dev/null || shift ;;
            --ki)     ki="${2:-}";     shift 2 2>/dev/null || shift ;;
            --opc)    opc="${2:-}";    shift 2 2>/dev/null || shift ;;
            --op)     op="${2:-}";     shift 2 2>/dev/null || shift ;;
            --top)    top="${2:-}";    shift 2 2>/dev/null || shift ;;
            --algo)   algo="${2:-}";   shift 2 2>/dev/null || shift ;;
            --sqn)    sqn="${2:-}";    shift 2 2>/dev/null || shift ;;
            --amf)    amf="${2:-}";    shift 2 2>/dev/null || shift ;;
            --reveal) reveal=1;        shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    [[ -n "$imsi" ]] || { sim_aka_usage; return 2; }
    [[ "$imsi" =~ ^[0-9]{5,15}$ ]] || {
        printf 'ERROR\t--imsi must be 5..15 decimal digits, got %d chars\n' "${#imsi}" >&2; return 2; }
    ki="${ki^^}"
    [[ "$ki" =~ ^[0-9A-F]{32}$ ]] || {
        printf 'ERROR\t--ki must be 32 hex digits (128-bit K), got %d\n' "${#ki}" >&2; return 2; }
    case "$algo" in
        milenage)
            (( ${#opc} )) && opc="${opc^^}"
            (( ${#op} ))  && op="${op^^}"
            if [[ -n "$top" ]]; then
                printf 'ERROR\t--top is a TUAK parameter; for milenage give --op or --opc\n' >&2
                return 2
            fi
            if [[ -n "$op" && -n "$opc" ]]; then
                printf 'ERROR\tgive --op or --opc, not both\n' >&2; return 2
            fi
            if [[ -n "$op" ]]; then
                [[ "$op" =~ ^[0-9A-F]{32}$ ]] || {
                    printf 'ERROR\t--op must be 32 hex digits, got %d\n' "${#op}" >&2; return 2; }
                opc=$(sim_kv opc "$(sim_cmd_sim_auth milenage "$ki" \
                        00000000000000000000000000000000 --op "$op" 2>/dev/null)")
                [[ "$opc" =~ ^[0-9A-F]{32}$ ]] || {
                    printf 'ERROR\tcould not derive OPC from that OP\n' >&2; return 1; }
            fi
            [[ "$opc" =~ ^[0-9A-F]{32}$ ]] || {
                printf 'ERROR\t--opc must be 32 hex digits (16 bytes), got %d\n' "${#opc}" >&2; return 2; }
            ;;
        tuak)
            [[ -n "$op" || -n "$opc" ]] && {
                printf 'ERROR\tOP/OPC belong to milenage; TUAK takes --top\n' >&2; return 2; }
            top="${top^^}"
            [[ "$top" =~ ^[0-9A-F]{64}$ ]] || {
                printf 'ERROR\t--top must be 64 hex digits (the TUAK TOP), got %d\n' "${#top}" >&2; return 2; }
            opc="$top"
            ;;
        *) printf 'ERROR\t--algo must be milenage or tuak\n' >&2; return 2 ;;
    esac
    sqn="${sqn^^}"
    [[ -z "$sqn" || "$sqn" =~ ^[0-9A-F]{12}$ ]] || {
        printf 'ERROR\t--sqn must be 12 hex digits (6 bytes), got %d\n' "${#sqn}" >&2; return 2; }
    amf="${amf^^}"
    [[ "$amf" =~ ^[0-9A-F]{4}$ ]] || {
        printf 'ERROR\t--amf must be 4 hex digits (2 bytes), got %d\n' "${#amf}" >&2; return 2; }
    : "${sqn:=000000000000}"

    local store prev
    store=$(sim_aka_ensure) || return 1
    prev=$(sim_aka_row "$imsi")
    # Adding over an existing IMSI keeps its vector count and only resets what
    # was given: re-keying a subscriber must not silently rewind SQN to zero,
    # because the network would then see a stale SQN as a replay.
    local vectors=0 keep_sqn=''
    if [[ -n "$prev" ]]; then
        IFS=$'\t' read -r _ _ _ _ keep_sqn _ vectors _ <<<"$prev"
        [[ "$sqn" == 000000000000 && -n "$keep_sqn" ]] && sqn="$keep_sqn"
    fi

    sim_aka_locked sim_aka_put "$imsi" "$ki" "$algo" "$opc" "$sqn" "$amf" "${vectors:-0}" || {
        printf 'ERROR\tcould not write the store\n' >&2; return 1; }

    printf 'stored\tyes\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'algo\t%s\n' "$algo"
    if (( reveal )); then
        printf 'ki\t%s\n' "$ki"
        printf 'secret2\t%s\n' "$opc"
    else
        printf 'ki_masked\t%s\n' "$(sim_aka_mask "$ki")"
        printf 'secret2_masked\t%s\n' "$(sim_aka_mask "$opc")"
        printf 'reveal\tno (--reveal prints K and OPC/TOP)\n'
    fi
    printf 'sqn\t%s\n' "$sqn"
    printf 'amf\t%s\n' "$amf"
    printf 'store\t%s\n' "${store#"$IMSISTING_ROOT"/}"
    printf 'store_mode\t%s\n' "$(stat -c %a "$store" 2>/dev/null || printf '?')"
    printf 'note\tK and OPC/TOP are the card secrets: the file is 0600 and in STATE_DIR, which is never committed\n'
    return 0
}

# ── --key-list / --key-show / --key-remove ──────────────────────────────
sim_cmd_key_list() {
    local reveal=0 store n
    while (( $# )); do
        case "$1" in
            --reveal) reveal=1; shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    store=$(sim_aka_ensure) || return 1
    n=$(sim_aka_live "$store")
    printf 'store\t%s\n' "${store#"$IMSISTING_ROOT"/}"
    printf 'store_mode\t%s\n' "$(stat -c %a "$store" 2>/dev/null || printf '?')"
    printf 'subscribers\t%s\n' "$n"
    (( n )) || printf 'note\tempty store: --key-add --imsi <digits> --ki <32hex> --opc <32hex> writes the first row\n'
    awk -F'\t' '!/^#/ && $1 != "" { print }' "$store" |
    while IFS=$'\t' read -r imsi ki algo secret2 sqn amf vectors updated; do
        printf 'imsi\t%s\n' "$imsi"
        printf 'algo\t%s\n' "$algo"
        if (( reveal )); then
            printf 'ki\t%s\n' "$ki"
            printf 'secret2\t%s\n' "$secret2"
        else
            printf 'ki_masked\t%s\n' "$(sim_aka_mask "$ki")"
            printf 'secret2_masked\t%s\n' "$(sim_aka_mask "$secret2")"
        fi
        printf 'sqn\t%s\n' "$sqn"
        printf 'vectors\t%s\n' "$vectors"
        printf 'updated\t%s\n' "$updated"
        printf 'row_end\t-\n'
    done
    return 0
}

sim_cmd_key_show() {
    local imsi='' reveal=0 row
    while (( $# )); do
        case "$1" in
            --imsi)   imsi="${2:-}"; shift 2 2>/dev/null || shift ;;
            --reveal) reveal=1; shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    [[ -n "$imsi" ]] || { sim_aka_usage; return 2; }
    row=$(sim_aka_row "$imsi")
    if [[ -z "$row" ]]; then
        printf 'ERROR\tno subscriber %s in the store; --key-list shows what is there\n' \
            "$(sim_sanitize "$imsi")" >&2
        return 1
    fi
    local ki algo secret2 sqn amf vectors updated
    IFS=$'\t' read -r _ ki algo secret2 sqn amf vectors updated <<<"$row"
    printf 'imsi\t%s\n' "$imsi"
    printf 'algo\t%s\n' "$algo"
    if (( reveal )); then
        printf 'ki\t%s\n' "$ki"
        printf 'secret2\t%s\n' "$secret2"
    else
        printf 'ki_masked\t%s\n' "$(sim_aka_mask "$ki")"
        printf 'secret2_masked\t%s\n' "$(sim_aka_mask "$secret2")"
        printf 'reveal\tno (--reveal prints K and OPC/TOP)\n'
    fi
    printf 'sqn\t%s\n' "$sqn"
    printf 'amf\t%s\n' "$amf"
    printf 'vectors\t%s\n' "$vectors"
    printf 'updated\t%s\n' "$updated"
    return 0
}

sim_cmd_key_remove() {
    local imsi=''
    while (( $# )); do
        case "$1" in
            --imsi) imsi="${2:-}"; shift 2 2>/dev/null || shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    [[ -n "$imsi" ]] || { sim_aka_usage; return 2; }
    local store
    store=$(sim_aka_ensure) || return 1
    if ! sim_aka_locked sim_aka_del "$imsi"; then
        printf 'ERROR\tno subscriber %s in the store\n' "$(sim_sanitize "$imsi")" >&2
        return 1
    fi
    printf 'removed\t%s\n' "$imsi"
    printf 'subscribers\t%s\n' "$(sim_aka_live "$store")"
    return 0
}

# ── --aka-responder ─────────────────────────────────────────────────────
# One AKA authentication event for one stored subscriber:
#   * RAND is supplied or drawn from /dev/urandom
#   * SQN comes from the store and is incremented afterwards (a USIM's job)
#   * the quintet comes from the same --sim-auth path everything else uses
#   * with --5g, the two KDF outputs the AUSF would need are derived too
# ── AUTS: the resynchronisation the network cannot refuse (R8) ─────────
#
# A USIM keeps its own SQN. When the network's AUTN carries an SQN that is not
# ahead of the card's, the card does not compute a vector and pretend: it
# answers AUTHENTICATION FAILURE with AUTS, which is (SQN_MS xor AK) || MAC-S
# (TS 33.102 6.3.5), so the network can see where the card actually is and move
# its counter forward. Without it one stale SQN makes every attach fail with no
# diagnosis -- the carrier-grade version of "it just doesn't work".
#
# MAC-S is f1* over the card's own SQN with AMF=0000 (the AUTS case), which is
# the one Milenage output that is only ever used here.
sim_auts_build() {  # <ki> <opc> <rand> <sqn_ms> [<amf>] -> rows
    local ki="${1:-}" opc="${2:-}" rand="${3:-}" sqn="${4:-}" amf="${5:-0000}"
    [[ -n "$ki" && -n "$opc" && -n "$rand" && -n "$sqn" ]] || {
        printf 'ERROR\tusage: --auts-build <ki-32hex> <opc-32hex> <rand-32hex> <sqn_ms-12hex> [<amf-4hex>]\n' >&2
        return 2; }
    [[ "$ki" =~ ^[0-9A-Fa-f]{32}$ ]] || { printf 'ERROR\tKi is 16 octets (32 hex)\n' >&2; return 2; }
    [[ "$opc" =~ ^[0-9A-Fa-f]{32}$ ]] || { printf 'ERROR\tOPc is 16 octets (32 hex)\n' >&2; return 2; }
    [[ "$rand" =~ ^[0-9A-Fa-f]{32}$ ]] || { printf 'ERROR\tRAND is 16 octets (32 hex)\n' >&2; return 2; }
    [[ "${sqn^^}" =~ ^[0-9A-F]{12}$ ]] || { printf 'ERROR\tSQN_MS is 6 octets (12 hex): %s\n' "$(sim_sanitize "$sqn")" >&2; return 2; }
    [[ "${amf^^}" =~ ^[0-9A-F]{4}$ ]] || { printf 'ERROR\tAMF is 2 octets (4 hex)\n' >&2; return 2; }
    sqn="${sqn^^}"; amf="${amf^^}"

    # AUTS uses the AUTS case: AMF = 0000 in the f1* computation regardless of
    # what the network's AUTN carried.
    local raw; raw=$(sim_cmd_sim_auth milenage "$ki" "$rand" --opc "$opc" --sqn "$sqn" --amf 0000 2>/dev/null) || {
        printf 'ERROR\tthe Milenage run failed\n' >&2; return 1; }
    local mac_s ak
    mac_s=$(sim_kv 'f1*' "$raw"); ak=$(sim_kv ak "$raw")
    [[ -n "$mac_s" && -n "$ak" ]] || { printf 'ERROR\tno f1* or f5 in the run\n' >&2; return 1; }
    local sqn_ak; sqn_ak=$(sim_auth_xor "$sqn" "$ak") || return 1
    printf 'auts\t%s%s\n' "$sqn_ak" "$mac_s"
    printf 'sqn_ms\t%s\n' "$sqn"
    printf 'ak\t%s\n' "$ak"
    printf 'mac_s\t%s\n' "$mac_s"
    printf 'autn_case_amf\t0000\n'
    printf 'octets\t%d\n' "$(( (${#sqn_ak} + ${#mac_s}) / 2 ))"
    printf 'ref\t3GPP TS 33.102 6.3.5 (AUTS = SQN_MS xor AK || MAC-S), TS 35.206 f1*\n'
}

sim_auts_verify() {  # <ki> <opc> <rand> <auts-28hex> -> rows
    local ki="${1:-}" opc="${2:-}" rand="${3:-}" auts="${4:-}"
    [[ -n "$ki" && -n "$opc" && -n "$rand" && -n "$auts" ]] || {
        printf 'ERROR\tusage: --auts-verify <ki-32hex> <opc-32hex> <rand-32hex> <auts-28hex>\n' >&2
        return 2; }
    [[ "${auts^^}" =~ ^[0-9A-F]{28}$ ]] || {
        printf 'ERROR\tAUTS is 14 octets (28 hex): %s\n' "$(sim_sanitize "$auts")" >&2; return 2; }
    auts="${auts^^}"
    local sqn_ak="${auts:0:12}" mac_s="${auts:12:16}"

    # AK comes from f5, which does not depend on SQN or AMF.
    local raw; raw=$(sim_cmd_sim_auth milenage "$ki" "$rand" --opc "$opc" --sqn 000000000000 --amf 0000 2>/dev/null) || {
        printf 'ERROR\tthe Milenage run failed\n' >&2; return 1; }
    local ak; ak=$(sim_kv ak "$raw")
    [[ -n "$ak" ]] || { printf 'ERROR\tno f5 in the run\n' >&2; return 1; }
    local sqn_ms; sqn_ms=$(sim_auth_xor "$sqn_ak" "$ak") || return 1

    local check; check=$(sim_cmd_sim_auth milenage "$ki" "$rand" --opc "$opc" --sqn "$sqn_ms" --amf 0000 2>/dev/null)
    local want_mac; want_mac=$(sim_kv 'f1*' "$check")
    [[ -n "$want_mac" ]] || { printf 'ERROR\tno f1* in the check run\n' >&2; return 1; }

    printf 'auts\t%s\n' "$auts"
    printf 'sqn_ak\t%s\n' "$sqn_ak"
    printf 'ak\t%s\n' "$ak"
    printf 'sqn_ms\t%s\n' "$sqn_ms"
    printf 'mac_s\t%s\n' "$mac_s"
    printf 'mac_s_computed\t%s\n' "$want_mac"
    if [[ "$mac_s" == "$want_mac" ]]; then
        printf 'verdict\tvalid\n'
        printf 'next_sqn\t%s\n' "$(( 16#$sqn_ms + 1 ))"
        printf 'next_sqn_hex\t%012X\n' "$(( 16#$sqn_ms + 1 ))"
        printf 'action\tthe network sets its SQN to SQN_MS + 1 and re-authenticates\n'
        return 0
    fi
    printf 'verdict\tinvalid\n'
    printf 'note\tMAC-S does not verify: the AUTS is forged, corrupted, or computed with another key\n'
    return 1
}

sim_cmd_auts_build()  { sim_auts_build "$@"; }
sim_cmd_auts_verify() { sim_auts_verify "$@"; }

# ── USIM over a socket: the card side of an attach (R7) ─────────────────
#
# Every earlier verb in this module speaks *to* a card or *as* the network. This
# one is the card: a 7816 APDU responder that a UE emulator can drive, so an
# attach needs no physical USIM. The commands are the ones a handset actually
# sends -- SELECT by AID or file id, READ BINARY, VERIFY, AUTHENTICATE, GET
# RESPONSE -- and the answer to AUTHENTICATE is computed from the key store by
# the same Milenage/TUAK path --aka-responder uses, with the SQN counter
# persisted per vector exactly as it is there.
#
# WHAT IS REAL: the APDU parse, the SELECT/READ state (which EF is current),
# the vector, the SQN increment, and the status words.
# WHAT IS NOT: no AUTS. A card returns 9862 with 14 octets of AUTS when the
# network's SQN is behind its own; f1* is not built here (R8), so this card
# never emits that path and says so instead of returning a made-up AUTS.
# EF_IMSI is served because the store knows the IMSI; EF_ICCID, EF_AD and the
# service tables are not served, because the store does not hold them and a
# card that invents a profile is worse than a card that reports 6A82.
SIM_USIM_AID_USIM="A0000000871002FF86"
SIM_USIM_AID_ISIM="A0000000871004"

sim_usim_ef_imsi() {  # <imsi> -> EF_IMSI content (length octet + BCD)
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || return 1
    local bcd; bcd=$(sim_bcd_encode "$imsi") || return 1
    printf '%02X%s' "$(( ${#bcd} / 2 ))" "$bcd"
}

sim_usim_serve() {
    local imsi="" reslen="8" persist=1
    while (( $# > 0 )); do
        case "$1" in
            --imsi)   imsi="${2:-}"; shift 2 ;;
            --reslen) reslen="${2:-8}"; shift 2 ;;
            --no-persist) persist=0; shift ;;
            -h|--help)
                printf 'usage: --usim-serve --imsi <imsi> [--reslen 4|8|16] [--no-persist]\n' >&2
                printf '       reads one hex C-APDU per line on stdin, answers one R-APDU per line\n' >&2
                return 0 ;;
            *) printf 'ERROR\t--usim-serve does not take %s\n' "$(sim_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ -n "$imsi" ]] || {
        printf 'ERROR\tusage: --usim-serve --imsi <imsi> [--reslen 4|8|16]\n' >&2; return 2; }
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(sim_sanitize "$imsi")" >&2; return 2; }
    local row; row=$(sim_aka_row "$imsi")
    if [[ -z "$row" ]]; then
        printf 'ERROR\tno subscriber %s in the key store; --key-add writes one\n' "$(sim_sanitize "$imsi")" >&2
        return 1
    fi
    [[ "$reslen" =~ ^(4|8|16)$ ]] || {
        printf 'ERROR\t--reslen is 4, 8 or 16 octets\n' >&2; return 2; }

    local ef_imsi; ef_imsi=$(sim_usim_ef_imsi "$imsi") || {
        printf 'ERROR\tthe IMSI could not be BCD-encoded\n' >&2; return 1; }

    local cur_df="3F00" cur_ef="" n=0 line h gots
    printf 'responder\tusim\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'store\t%s\n' "$(sim_aka_store)"
    printf 'serves\tEF_IMSI (6F07)\n'
    printf 'not_served\tEF_ICCID, EF_AD, EF_UST: the store holds no profile for them\n'

    # `|| [[ -n $line ]]` is load-bearing: a client that sends its last APDU
    # without a trailing newline would otherwise have that APDU swallowed.
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue
        n=$(( n + 1 ))
        local hdr
        hdr=$(sim_parse_capdu "$line" 2>/dev/null) || {
            printf 'apdu\t%s\n' "$(sim_sanitize "$line")"
            printf 'sw\t6700\n'
            printf 'status\t%s\n' "$(sim_sw_label 6700)"
            printf 'note\tthe input is not a well-formed C-APDU\n'
            continue; }
        local cla ins p1 p2 data
        cla=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="cla"{print $2; exit}')
        ins=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="ins"{print $2; exit}')
        p1=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="p1"{print $2; exit}')
        p2=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="p2"{print $2; exit}')
        data=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="data"{print $2; exit}')
        local sw="6D00" resp="" cmd="unknown" note=""

        # Class: 00/80 are the plain classes; anything with the secure-messaging
        # bit set is refused rather than guessed (this card has no SCP).
        if (( (16#$cla & 0x0C) != 0 )); then
            sw="6E00"; cmd="secure messaging"; note="this card has no secure messaging"
        else
            case "$ins" in
                A4)
                    cmd="SELECT"
                    if [[ "$p1" == "04" ]]; then
                        # The AID a handset sends is the RID plus the USIM
                        # application code and whatever proprietary tail its
                        # card vendor uses, so the match is on the prefix that
                        # TS 31.102 defines, not on the whole string.
                        local aid="${data:0:14}"
                        if [[ "$aid" == "${SIM_USIM_AID_USIM:0:14}" || "$aid" == "${SIM_USIM_AID_ISIM:0:14}" ]]; then
                            cur_df="7FFF"; cur_ef=""; sw="9000"
                            resp="621F8202$SIM_USIM_AID_USIM"
                            note="USIM application selected"
                        else
                            sw="6A82"; note="no application with that AID on this card"
                        fi
                    elif [[ "$p1" == "00" ]]; then
                        local fid="${data:0:4}"
                        case "$fid" in
                            3F00|7FFF|7F20|7F10) cur_df="$fid"; cur_ef=""; sw="9000"; note="DF selected" ;;
                            6F07) cur_ef="6F07"; sw="9000"; resp="$ef_imsi"; note="EF_IMSI selected (content returned in the FCI)" ;;
                            6F38|2FE2|6FAD)
                                cur_ef="$fid"; sw="6A82"
                                note="$(sim_file_name "$fid" | cut -d'|' -f1) is not served: the store holds no content for it" ;;
                            *) sw="6A82"; note="no such file on this card" ;;
                        esac
                    else
                        sw="6A86"; note="only SELECT by AID (P1=04) or by file id (P1=00) is supported"
                    fi ;;
                B0)
                    cmd="READ BINARY"
                    if [[ -z "$cur_ef" ]]; then
                        sw="6986"; note="no EF selected"
                    elif [[ "$cur_ef" != "6F07" ]]; then
                        sw="6A82"; note="the selected file is not served"
                    else
                        local off=$(( 16#$p1 * 256 + 16#$p2 ))
                        local total=$(( ${#ef_imsi} / 2 ))
                        if (( off >= total )); then
                            sw="6B00"; note="offset outside EF_IMSI ($total octets)"
                        else
                            resp="${ef_imsi:$(( off * 2 ))}"
                            sw="9000"
                            note="EF_IMSI from offset $off"
                        fi
                    fi ;;
                20)
                    cmd="VERIFY"
                    # The store has no PIN record, so this card cannot check one.
                    # It says so rather than pretending the PIN was verified.
                    sw="9000"
                    note="no PIN record in the store: this card does not authenticate a PIN" ;;
                88)
                    cmd="AUTHENTICATE"
                    if [[ "$p1" == "81" ]]; then
                        if (( ${#data} != 64 )); then
                            sw="6700"; note="3G AUTHENTICATE carries RAND (16) and AUTN (16) octets"
                        else
                            # RAND occupies the first 16 octets; the AUTN
                            # follows it, and its first 6 octets are the
                            # SQN masked with AK (TS 33.102 6.3.3).
                            local r_rand="${data:0:32}" sqn_ak="${data:32:12}"
                            local arow _k ki_a algo_a opc_a sqn_a amf_a r_ak r_net
                            arow=$(sim_aka_row "$imsi")
                            IFS=$'\t' read -r _k ki_a algo_a opc_a sqn_a amf_a _ <<<"$arow"
                            # AK (f5) does not depend on SQN or AMF, so one run
                            # with dummy values gives the value the AUTN was
                            # masked with, and SQN_net = (SQN xor AK) xor AK.
                            if [[ -n "$ki_a" && -n "$opc_a" ]]; then
                                local araw
                                if [[ "$algo_a" == tuak ]]; then
                                    araw=$(sim_cmd_sim_auth tuak "$ki_a" "$r_rand" --top "$opc_a" \
                                            --sqn 000000000000 --amf 0000 2>/dev/null)
                                else
                                    araw=$(sim_cmd_sim_auth milenage "$ki_a" "$r_rand" --opc "$opc_a" \
                                            --sqn 000000000000 --amf 0000 2>/dev/null)
                                fi
                                r_ak=$(sim_kv ak "$araw")
                            fi

                            if [[ -n "$r_ak" ]]; then
                                r_net=$(sim_auth_xor "$sqn_ak" "$r_ak") || r_net=""
                            fi

                            if [[ -n "$r_net" ]] && (( 16#$r_net <= 16#${sqn_a:-000000000000} )); then
                                # The network is behind this card. Computing a
                                # vector over a stale SQN is exactly how an
                                # attach fails with no diagnosis, so the card
                                # answers AUTHENTICATION FAILURE with AUTS and
                                # lets the network resynchronise.
                                local auts_row auts_hex
                                auts_row=$(sim_auts_build "$ki_a" "$opc_a" "$r_rand" "$sqn_a")
                                auts_hex=$(printf '%s\n' "$auts_row" | awk -F'\t' '$1=="auts"{print $2; exit}')
                                if [[ -n "$auts_hex" ]]; then
                                    resp="$auts_hex"; sw="9862"
                                    note="the network's SQN $r_net is not ahead of the card's $sqn_a: AUTS returned so the network can resynchronise"
                                else
                                    sw="9862"
                                    note="the network's SQN is not ahead of the card's and AUTS could not be built"
                                fi
                            else
                                local rand="$r_rand" vec res ck ik
                                vec=$(sim_cmd_aka_responder --imsi "$imsi" --rand "$rand" 2>/dev/null)
                                # xres is what the store publishes; on this side of
                                # the card it IS the RES the handset will send back.
                                res=$(sim_kv xres "$vec"); ck=$(sim_kv ck "$vec"); ik=$(sim_kv ik "$vec")
                                if [[ -z "$res" || -z "$ck" || -z "$ik" ]]; then
                                    sw="6F00"; note="the key store produced no vector for this subscriber"
                                else
                                    case "$reslen" in
                                        4) res="${res:0:8}" ;;
                                        8) res="${res:0:16}" ;;
                                        16) res="${res:0:32}" ;;
                                    esac
                                    resp="${res}${ck}${ik}"
                                    sw="9000"
                                    note="RES($(( ${#res} / 2 )) octets) || CK || IK from the key store"
                                fi
                            fi
                        fi
                    elif [[ "$p1" == "80" ]]; then
                        # The 2G AUTHENTICATE is the GSM access path (COMP128
                        # SRES/Kc), not the USIM one. This card is a USIM over
                        # Milenage/TUAK, so it refuses by name rather than
                        # computing SRES from a key it was not provisioned with.
                        sw="6A86"
                        note="P1=80 is the GSM AUTHENTICATE: this card serves the USIM path (P1=81) only"
                    else
                        sw="6A86"; note="only P1=81 (3G) and P1=80 (2G) AUTHENTICATE are built"
                    fi ;;
                C0)
                    cmd="GET RESPONSE"; sw="9000"; note="nothing further to collect" ;;
                F2)
                    cmd="STATUS"; sw="6A81"; note="STATUS is not served: no card manager state is modelled" ;;
                *)
                    sw="6D00"; note="instruction not supported by this card" ;;
            esac
        fi

        printf 'apdu\t%s\n' "$(sim_sanitize "$line")"
        printf 'ins\t0x%s\n' "$ins"
        printf 'command\t%s\n' "$cmd"
        [[ -n "$cur_ef" ]] && printf 'selected\t%s\n' "$cur_ef"
        printf 'sw\t%s\n' "$sw"
        printf 'status\t%s\n' "$(sim_sw_label "$sw")"
        [[ -n "$resp" ]] && printf 'response\t%s\n' "$resp"
        [[ -n "$note" ]] && printf 'note\t%s\n' "$note"
        # The card's answer, in the form a UE reads off the wire.
        printf 'rapdu\t%s%s\n' "$resp" "$sw"
    done
    printf 'exchanges\t%s\n' "$n"
    printf 'sent\t0\n'
    printf 'limit\tthis is the card side of the attach and not the network side: the vector comes from the key store and the file system serves EF_IMSI only; AUTS is not built (R8)\n'
    return 0
}

# The same responder over a TCP socket, for a UE emulator that expects a card
# on a port rather than on stdin. socat forks one responder per connection and
# the state (SQN) lives in the store, so two connections share one card.
sim_cmd_usim_tcp() {
    local port="${1:-}" imsi=""
    shift 2>/dev/null || true
    while (( $# > 0 )); do
        case "$1" in
            --imsi) imsi="${2:-}"; shift 2 ;;
            *) printf 'ERROR\t--usim-tcp does not take %s\n' "$(sim_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || {
        printf 'ERROR\tusage: --usim-tcp <port> --imsi <imsi>\n' >&2; return 2; }
    [[ -n "$imsi" ]] || { printf 'ERROR\tusage: --usim-tcp <port> --imsi <imsi>\n' >&2; return 2; }
    command -v socat >/dev/null 2>&1 || {
        printf 'ERROR\tsocat is needed to listen on a port and it is not on PATH\n' >&2; return 1; }
    printf 'listener\ttcp:%s\n' "$port"
    printf 'responder\tusim --imsi %s\n' "$imsi"
    printf 'sent\t0\n'
    printf 'limit\tthe socket carries APDUs both ways; nothing is put on the air\n'
    exec socat "TCP-LISTEN:$port,reuseaddr,fork" \
        "EXEC:${BASH_SOURCE[0]} --usim-serve --imsi $imsi"
}

sim_cmd_aka_responder() {
    local imsi='' rand='' sqn='' sn='' sn_name='' fiveg=0 persist=1
    while (( $# )); do
        case "$1" in
            --imsi)    imsi="${2:-}";    shift 2 2>/dev/null || shift ;;
            --rand)    rand="${2:-}";    shift 2 2>/dev/null || shift ;;
            --sqn)     sqn="${2:-}";     shift 2 2>/dev/null || shift ;;
            --sn)      sn="${2:-}";      shift 2 2>/dev/null || shift ;;
            --sn-name) sn_name="${2:-}"; shift 2 2>/dev/null || shift ;;
            --5g)      fiveg=1;          shift ;;
            --no-persist) persist=0;     shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    [[ -n "$imsi" ]] || { sim_aka_usage; return 2; }
    local row
    row=$(sim_aka_row "$imsi")
    if [[ -z "$row" ]]; then
        printf 'ERROR\tno subscriber %s in the store; --key-add writes one\n' \
            "$(sim_sanitize "$imsi")" >&2
        return 1
    fi
    local ki algo secret2 st_sqn amf vectors updated
    IFS=$'\t' read -r _ ki algo secret2 st_sqn amf vectors updated <<<"$row"
    st_sqn="${st_sqn^^}"; amf="${amf^^}"
    : "${st_sqn:=000000000000}"
    : "${amf:=B9B9}"

    rand="${rand^^}"
    if [[ -z "$rand" ]]; then
        rand=$(sim_aka_rand) || return 1
    fi
    [[ "$rand" =~ ^[0-9A-F]{32}$ ]] || {
        printf 'ERROR\tRAND must be 32 hex digits (16 bytes), got %d\n' "${#rand}" >&2; return 2; }
    if [[ -n "$sqn" ]]; then
        sqn="${sqn^^}"
        [[ "$sqn" =~ ^[0-9A-F]{12}$ ]] || {
            printf 'ERROR\t--sqn must be 12 hex digits (6 bytes), got %d\n' "${#sqn}" >&2; return 2; }
    else
        sqn="$st_sqn"
    fi

    local sn_hex='' sn_rc=0
    if (( fiveg )); then
        sn_hex=$(sim_aka_sn_hex "$sn" "$sn_name") || sn_rc=$?
        (( sn_rc == 2 )) && return 2
        if [[ -z "$sn_hex" ]]; then
            printf 'ERROR\t--5g needs the serving network name: --sn <hex> or --sn-name <text>\n' >&2
            printf 'ERROR\tthe KDF input is the SN name verbatim (TS 33.501 A.4.1, e.g. 5G:mnc001.mcc001.3gppnetwork.org)\n' >&2
            return 2
        fi
    elif [[ -n "$sn" || -n "$sn_name" ]]; then
        printf 'ERROR\t--sn/--sn-name only mean something with --5g\n' >&2
        return 2
    fi

    local raw res ck ik ak maca autn
    if [[ "$algo" == tuak ]]; then
        raw=$(sim_cmd_sim_auth tuak "$ki" "$rand" --top "$secret2" --sqn "$sqn" --amf "$amf" 2>/dev/null) || {
            printf 'ERROR\tTUAK run failed for %s\n' "$(sim_sanitize "$imsi")" >&2; return 1; }
    else
        raw=$(sim_cmd_sim_auth milenage "$ki" "$rand" --opc "$secret2" --sqn "$sqn" --amf "$amf" 2>/dev/null) || {
            printf 'ERROR\tMilenage run failed for %s\n' "$(sim_sanitize "$imsi")" >&2; return 1; }
    fi
    res=$(sim_kv res "$raw"); ck=$(sim_kv ck "$raw"); ik=$(sim_kv ik "$raw")
    ak=$(sim_kv f5 "$raw");   maca=$(sim_kv f1 "$raw"); autn=$(sim_kv autn "$raw")
    [[ -n "$res" && -n "$ck" && -n "$ik" && -n "$autn" ]] || {
        printf 'ERROR\tthe auth run produced no complete vector\n' >&2; return 1; }

    local kausf_hex='' res_star_hex='' sqn_ak akey
    if (( fiveg )); then
        # The KDF key is CK||IK, not K (TS 33.501 A.4.1). Every 5G derivation
        # below uses that concatenation; with K a core would reject the vector.
        akey="${ck}${ik}"
        sqn_ak=$(sim_auth_xor "$sqn" "$ak")
        kausf_hex=$(sim_aka_derive kausf --ck "${akey:0:32}" --ik "${akey:32:32}" \
                        --sn "$sn_hex" --sqn-ak "$sqn_ak") || {
            printf 'ERROR\tKAUSF derivation failed\n' >&2; return 1; }
        res_star_hex=$(sim_aka_derive res-star --ck "${akey:0:32}" --ik "${akey:32:32}" \
                        --sn "$sn_hex" --rand "$rand" --res "$res") || {
            printf 'ERROR\tRES* derivation failed\n' >&2; return 1; }
        [[ -n "$kausf_hex" && -n "$res_star_hex" ]] || {
            printf 'ERROR\tthe KDF returned nothing\n' >&2; return 1; }
    fi

    if (( persist )); then
        vectors=$(( ${vectors:-0} + 1 ))
        sim_aka_locked sim_aka_put "$imsi" "$ki" "$algo" "$secret2" \
            "$(sim_aka_sqn_inc "$sqn")" "$amf" "$vectors" || {
            printf 'ERROR\tvector computed but the SQN counter could not be persisted\n' >&2
            return 1; }
    fi

    printf 'imsi\t%s\n' "$imsi"
    printf 'algo\t%s\n' "$algo"
    local mode='eps-aka'
    (( fiveg )) && mode='5g'
    printf 'mode\t%s\n' "$mode"
    printf 'rand\t%s\n' "$rand"
    printf 'xres\t%s\n' "$res"
    printf 'ck\t%s\n' "$ck"
    printf 'ik\t%s\n' "$ik"
    printf 'autn\t%s\n' "$autn"
    printf 'sqn\t%s\n' "$sqn"
    printf 'amf\t%s\n' "$amf"
    printf 'sqn_next\t%s\n' "$(sim_aka_sqn_inc "$sqn")"
    printf 'vector_count\t%s\n' "${vectors:-0}"
    if (( fiveg )); then
        printf 'sn\t%s\n' "$sn_hex"
        printf 'sn_text\t%s\n' "$(sim_aka_sn_text "$sn_hex")"
        printf 'kausf\t%s\n' "$kausf_hex"
        printf 'res_star\t%s\n' "$res_star_hex"
        printf 'kdf_source\tTS 33.220 Annex B.2 KDF: FC=6A over (SN, SQN xor AK), FC=6B over (SN, RAND, RES)\n'
    fi
    printf 'note\tXRES is the network side of RES: the card computes RES on the same input; this is the AuC half\n'
    printf 'note\tAUTS/resynchronisation is not built: it needs SQN_MS from the peer, not from this store\n'
    return 0
}

sim_aka_sn_text() { # <hex> -> the text form, if every byte is printable
    local h="${1:-}" out='' i c
    (( ${#h} % 2 == 0 )) || return 1
    for (( i = 0; i < ${#h}; i += 2 )); do
        c=$(( 16#${h:i:2} ))
        if (( c < 32 || c > 126 )); then return 1; fi
        out+=$(printf '%b' "$(printf '\\%03o' "$c")")
    done
    printf '%s' "$out"
}

# ── --aka-serve ─────────────────────────────────────────────────────────
# The resident responder: one long-lived process, a request per line, SQN
# walked on disk between requests. Requests:
#   VECTOR <imsi> [<rand-hex>]     one authentication event
#   LIST                           what the store holds
#   QUIT                           leave
# Every request prints its rows, then `result ok|error`.
sim_cmd_aka_serve() {
    local fiveg=0 sn='' sn_name=''
    while (( $# )); do
        case "$1" in
            --5g)      fiveg=1;          shift ;;
            --sn)      sn="${2:-}";      shift 2 2>/dev/null || shift ;;
            --sn-name) sn_name="${2:-}"; shift 2 2>/dev/null || shift ;;
            -h|--help) sim_aka_usage; return 0 ;;
            *) sim_aka_usage; return 2 ;;
        esac
    done
    local store served=0 rejected=0 line verb a1 a2 out rc n=0
    store=$(sim_aka_ensure) || return 1
    printf 'serve\tready\n'
    printf 'store\t%s\n' "${store#"$IMSISTING_ROOT"/}"
    printf 'protocol\tVECTOR <imsi> [<rand>] | LIST | QUIT\n'
    while IFS= read -r line; do
        # Trim, then split into at most three words: the line protocol has no
        # quoting, so a tab or a space inside an argument is a rejection, not
        # a parse decision made here.
        line="${line%%[[:cntrl:]]*}"
        read -r verb a1 a2 <<<"$line" || true
        verb="${verb:-}"
        [[ -z "$verb" ]] && continue
        n=$(( n + 1 ))
        printf 'request\t%s\n' "$verb"
        case "${verb^^}" in
            VECTOR)
                local -a args=(--imsi "${a1:-}")
                [[ -n "${a2:-}" ]] && args+=(--rand "$a2")
                (( fiveg )) && args+=(--5g)
                [[ -n "$sn" ]] && args+=(--sn "$sn")
                [[ -n "$sn_name" ]] && args+=(--sn-name "$sn_name")
                if out=$(sim_cmd_aka_responder "${args[@]}" 2>&1); then
                    printf '%s\n' "$out"
                    printf 'result\tok\n'
                    served=$(( served + 1 ))
                else
                    printf '%s\n' "$out"
                    printf 'result\terror\n'
                    rejected=$(( rejected + 1 ))
                fi
                ;;
            LIST)
                out=$(sim_cmd_key_list)
                rc=$?
                printf '%s\n' "$out"
                if (( rc == 0 )); then printf 'result\tok\n'; else printf 'result\terror\n'; fi
                served=$(( served + 1 ))
                ;;
            QUIT|EXIT)
                printf 'result\tbye\n'
                break
                ;;
            *)
                printf 'ERROR\tunknown request %s; VECTOR <imsi> [<rand>], LIST, QUIT\n' \
                    "$(sim_sanitize "$verb")"
                printf 'result\terror\n'
                rejected=$(( rejected + 1 ))
                ;;
        esac
    done
    printf 'served\t%s\n' "$served"
    printf 'rejected\t%s\n' "$rejected"
    printf 'requests\t%s\n' "$n"
    # A rejection here is the protocol working: an unknown IMSI or an unparsable
    # line is answered with ERROR and the loop keeps the SQN walk intact. There
    # is therefore no PASS/FAIL row — the counters are the report.
    return 0
}

# ── CLI dispatch ────────────────────────────────────────────────────────
sim_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     sim_cli_status_tsv ;;
        --build-apdu)     sim_cmd_build_apdu "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
        --parse-apdu)     sim_cmd_parse_apdu "${1:-}" ;;
        --decode-iccid)   sim_cmd_decode_iccid "${1:-}" ;;
        --decode-imsi)    sim_cmd_decode_imsi "${1:-}" ;;
        --decode-ad)      sim_cmd_decode_ad "${1:-}" ;;
        --parse-ota)      sim_cmd_parse_ota "${1:-}" ;;
        --spi)            sim_spi_decode "${1:-}" ;;
        --ota-key)        sim_cmd_ota_key "${1:-}" "${2:-}" ;;
        --select-fid)     sim_cmd_select "${1:-}" ;;
        --read-binary)    sim_cmd_read_binary "${1:-0}" "${2:-0}" ;;
        --read-record)    sim_cmd_read_record "${1:-1}" "${2:-04}" "${3:-0}" ;;
        --get-response)   sim_cmd_get_response "${1:-0}" ;;
        --file-id)        sim_file_name "${1:-}" ;;
        --plan)           sim_cmd_plan "${1:-}" ;;
        --dpa-model)      sim_dpa_model "${1:-}" "${2:-}" ;;
        --dpa-sim)        sim_dpa_sim "${1:-}" "${2:-}" "${3:-}" ;;
        --dpa-sweep)      sim_dpa_sweep "${1:-}" ;;
        --rsp)            sim_rsp_roles ;;
        --sim-auth)       sim_cmd_sim_auth "$@" ;;
        --sim-auth-check) sim_cmd_sim_auth_check ;;
        --key-add)        sim_cmd_key_add "$@" ;;
        --key-list)       sim_cmd_key_list "$@" ;;
        --key-show)       sim_cmd_key_show "$@" ;;
        --key-remove)     sim_cmd_key_remove "$@" ;;
        --aka-responder)  sim_cmd_aka_responder "$@" ;;
        --aka-serve)      sim_cmd_aka_serve "$@" ;;
        --auts-build)     sim_cmd_auts_build "$@" ;;
        --rsp-audit)      sim_rsp_audit "$@" ;;
        --profile-model)  sim_profile_model "${1:--}" ;;
        --rsp-plan)       sim_rsp_plan "${1:-}" ;;
        --auts-verify)    sim_cmd_auts_verify "$@" ;;
        --usim-serve)     sim_usim_serve "$@" ;;
        --usim-tcp)       sim_cmd_usim_tcp "$@" ;;
        --es9-plus)       sim_cmd_es9_plus "$@" ;;
        --es8-scp03t)     sim_cmd_es8_scp03t "$@" ;;
        --es8-build)      sim_cmd_es8_build "$@" ;;
        --es8-parse)      sim_cmd_es8_parse "${1:-}" ;;
        --es9-response)   sim_cmd_es9_response "$@" ;;
        --es9-notification) sim_cmd_es9_notification "${1:-}" ;;
        --selftest)       sim_selftest ;;
        --menu)           sim_menu ;;
        *)
            cat >&2 <<EOF
SIM / eSIM / OTA Attacks — ISO-7816 APDU, USIM files, TS 23.048 OTA, SGP.22 eSIM

Usage: $0 COMMAND
  --status-tsv                      reader/tool/log state as TSV
  --build-apdu CLA INS P1 P2 [DATA] [LE]   build a command APDU
  --parse-apdu <hex>                parse a command or response APDU
  --select-fid <fid>                SELECT APDU for a USIM file id
  --read-binary <offset> <le>       READ BINARY APDU
  --read-record <rec> [mode] [le]   READ RECORD APDU (mode 04 = absolute)
  --get-response <le>               GET RESPONSE APDU
  --file-id <fid>                   name of a USIM file id
  --decode-iccid <hex>              EF_ICCID (10 BCD octets) -> ICCID, Luhn checked
  --decode-imsi <hex>               EF_IMSI -> IMSI, length byte and parity nibble
  --decode-ad <hex>                 EF_AD -> PIN/PUK/ADM flags
  --parse-ota <hex>                 OTA SMS TPDU -> TAR, SPI, KIc/KID, CNTR
  --ota-key <KIc> [<KID>]           one or both key identifiers -> key set, mode, strength
  --spi <decimal>                   SPI bit-field decode
  --rsp                             eSIM RSP roles and profile states
  --dpa-model <ki> <rand>           COMP128-1 level-0 DPA leakage point per key byte
  --dpa-sim <ki> [traces] [sigma]   synthetic-trace DPA; key proven on held-out challenges
  --dpa-sweep <ki>                  DPA noise / trace-count / leakage-model sweeps
  --sim-auth <algo> <ki> <rand> [--op|--opc <hex>] [--sqn <hex>] [--amf <hex>] [--top <hex>] [--klength 128|256] [--iterations 1|2]
                                    COMP128-1/2/3, Milenage or TUAK vector: SRES/Kc or RES/CK/IK/AUTN
  --sim-auth-check                  published known-answer vectors through --sim-auth
  --key-add --imsi <digits> --ki <32hex> (--opc <hex>|--op <hex>|--top <64hex>) [--algo milenage|tuak] [--sqn <hex>] [--amf <hex>]
                                    store a subscriber's K and OPC/TOP in STATE_DIR (mode 0600)
  --key-list [--reveal]             stored subscribers, secrets masked unless --reveal
  --key-show --imsi <digits> [--reveal]   one stored subscriber
  --key-remove --imsi <digits>      drop a subscriber
  --aka-responder --imsi <digits> [--rand <hex>] [--sqn <hex>] [--5g --sn <hex>|--sn-name <text>]
                                    one AKA event: quintet from the store, SQN incremented and saved; --5g adds KAUSF and RES*
  --aka-serve [--5g --sn <hex>|--sn-name <text>]
                                    resident responder: VECTOR <imsi> [<rand>] / LIST / QUIT on stdin
  --profile-model <events-file>     run a sequence of profile operations
                                    (install|enable|disable|delete <iccid>, list)
                                    through the SGP.22 2.6.1 state machine and
                                    name every step the spec forbids
  --rsp-audit <response-json> [--request <json>] [--eid <hex>]
                                    audit an ES9+ exchange for the three ties
                                    that stop a profile being moved: transaction,
                                    SM-DP+ signature, EID
  --rsp-plan <profile-move|notification-spoof|smdp-redirect>
                                    what each RSP attack needs, as a handoff
  --auts-build <ki> <opc> <rand> <sqn_ms> [<amf>]
                                    the AUTS a card sends when the network's SQN
                                    is behind: (SQN_MS xor AK) || MAC-S
  --auts-verify <ki> <opc> <rand> <auts>
                                    the network side: recover SQN_MS and check
                                    MAC-S, so a resync is diagnosed not guessed
  --usim-serve --imsi <digits> [--reslen 4|8|16]
                                    be the card: one hex C-APDU per line on stdin,
                                    one R-APDU back (SELECT, READ BINARY, VERIFY,
                                    AUTHENTICATE P1=81, GET RESPONSE)
  --usim-tcp <port> --imsi <digits>
                                    the same card on a TCP socket, one socat fork
                                    per connection; the SQN lives in the store
  --es9-plus <op> --smds <host[:port]> [flags]
                                    SGP.22 ES9+ HTTP/JSON request builder; nothing is sent
  --es8-build <segment> [flags]     SGP.22 ES8+ TLV builder (5.5.1..5.5.5): bpp-header,
                                    initialise-secure-channel, configure-isdp, store-metadata,
                                    replace-session-keys, sequence-87|88|86, bpp
  --es8-parse <hex>                 walk a Bound Profile Package TLV by TLV: depth, tag, len, clause
  --es8-scp03t --k-enc <32hex> --k-mac <32hex> --host-challenge <16hex>
                                    --card-challenge <16hex> [--payload <hex>]
                                    the SCP03t command TLVs (84/85/86): session keys,
                                    cryptograms and the encrypted package segments
  --es9-response <op> <json>        parse an ES9+ response body (6.5.1.4 header + 6.5.2.x fields)
  --es9-notification <json>         parse ES9+.HandleNotification (6.5.2.9) and the ASN.1 it carries
  --plan <ota-replay|sat-wib|esim-download|apdu-live|dpa-lab>
                                    write a handoff plan naming the hardware
  --selftest                        verify encoders/decoders without a reader
  --menu                            interactive menu
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
    sim_cli_main "$@"
fi
