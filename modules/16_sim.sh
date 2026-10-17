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
        6C*)  echo "wrong Le: retry with Le=${sw:2:2}" ;;
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
            if [[ -n "$le" ]]; then case="4E"; body+=$(sim_word "$(( 16#$le ))"); le_out="$(( 16#$le ))"; fi
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
    local oa="" pid="" dcs="" scts="" udl="" udstart=0
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
        # SMS-SUBMIT: MTI|RD|VPF|SRR|UDHI|RP|MMS|0, then MR, DA, PID, DCS, VP, UDL, UD
        local daalen; daalen=$(sim_hex_dec "${h:2:2}")
        local daabytes=$(( (daalen + 1) / 2 ))
        local p=$(( 2 + 2 + daabytes * 2 ))
        pid="${h:$p:2}"; p=$(( p + 2 ))
        dcs="${h:$p:2}"; p=$(( p + 2 ))
        scts=""
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
    printf 'mti\t%s\nmti_code\t%s\nudhi\t%s\noa\t%s\npid\t%s\ndcs\t%s\ndcs_meaning\t%s\nscts\t%s\nudl\t%s\nud_bytes\t%s\nud\t%s\nudh_present\t%s\n' \
        "$mti_txt" "$mti" "$udhi" "$oa" "$pid" "${dcs:-}" "$dcs_txt" "$scts" "$udl" "$udbytes" "$ud" \
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

# ── selftest — no reader, no root, no network ───────────────────────────
sim_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
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
    chk sw-6c1c      "$(sim_sw_label 6C1C)" "wrong Le: retry with Le=1C"
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
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
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
