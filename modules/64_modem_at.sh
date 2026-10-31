#!/usr/bin/env bash
# 64_modem_at — the AT command surface: the modem's own management port. (tag: at)
#
# WHAT THIS IS. A cellular module is a second computer: its own CPU, firmware,
# TCP stack and calibration store, reachable over a serial line by a text
# protocol (3GPP TS 27.007 for the general set, TS 27.005 for SMS, TS 27.010
# for the multiplexer that carries it). Nothing in this tree opened that port
# before this module. Every other module needs an antenna, a capture or a core
# that answers; this one needs a tty, and a tty is present on a dongle, a CPE,
# an IoT board and a handset in diag mode.
#
# The pair to 56_baseband_diag, deliberately: that module is one vendor's
# binary framing (Qualcomm DM/DIAG, 133-byte NV records, CRC-16/X-25); this one
# is the text protocol every vendor speaks. Two protocol surfaces, one binary
# and one textual, and neither duplicates the other.
#
# WHAT THIS IS NOT. It does not extract Ki or OPc. Those live in UICC memory
# that only ever leaves as a computation, and AT+CSIM/AT+CRSM give you the
# files the key protects and the AKA oracle, not the key. It does not decrypt
# traffic whose keys you do not hold. It does not sample RF — an SDR sees the
# air, this asks the modem what it thinks of the air, and every field below
# says which of the two it is.
#
# NOTHING HERE IS GATED. --at-ctrl, --at-nv write and --at-stack send real
# commands to a real device and the device acts on them. That is deliberate and
# it is the same position 56_baseband_diag takes on --nv-write: these are raw
# primitives an operator drives with the arguments they choose. What this
# module refuses is a port that is not there, and it refuses by naming it.
#
# THE DOCTRINE APPLIED TO A VENDOR PAGE. An engineering page is ADVERTISED, not
# measured: the modem reports its own idea of the serving cell. Every row this
# module writes says so in the `source` column, and a field the vendor grammar
# does not carry is written as `not-advertised` rather than as a plausible zero.
# That is the difference between a survey and a guess, and it is why --at-eng
# emits the same sixteen columns 02_cell_recon does: a modem survey and a radio
# survey land in one store and one of them is marked as second-hand.
#
# TESTING WITHOUT HARDWARE. Every port operation goes through at_cmd(), which
# dispatches to a fake tty when MODEM_AT_FAKE names a directory of canned
# responses. The selftest builds that directory from the same at_fake_key()
# the runtime uses, so the fixture names cannot drift from the lookups, and the
# whole parser — identity, engineering decode, EF walk, verdict classifier — is
# exercised with no radio, no root and no device.
#
# CLAUSE MAP (every asserted value is recomputed here, never trusted):
#   [3GPP TS 27.007]  +CGSN +CIMI +CCID +CGMI +CGMM +CGMR +CPIN +COPS +CREG
#                     +CEREG +CSQ +CFUN +CLCK +CGDCONT +CRSM +CSIM +WS46
#   [3GPP TS 31.102]  EF_AD §4.2.18 (MNC length in the low nibble of byte 4)
#                     EF_IMSI §4.2.2, EF_SPN §4.2.12 (alpha is one 7-bit
#                     character per octet, 0xFF padding), EF_ICCID
#   [3GPP TS 23.038]  GSM 7-bit default alphabet (§6.2.1) — the unpacker below
#   [3GPP TS 23.003]  MCC/MNC are 3+2 or 3+3 digits; the split is per-country
#                     and NOT derivable from the digits, so EF_AD wins and the
#                     fallback carries its own confidence marker
#   [3GPP TS 23.040]  the +CME ERROR / +CMS ERROR codes named in at_sw_name
#   [ISO 7816-4]      SW1SW2 status words
#   vendor           +QENG/+QNWINFO (Quectel), !GSTATUS (Sierra),
#                     ^SYSINFO (Huawei), +QNVFR/+QNVFW (Quectel), +EGMR (MTK)
#                    — each marked as vendor grammar in the `source` column,
#                     because a vendor dialect is advertised twice over.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _at_src="${BASH_SOURCE[0]}"
    while [ -L "$_at_src" ]; do
        _at_dir="$(cd -P "$(dirname "$_at_src")" && pwd)"
        _at_tgt="$(readlink "$_at_src")"
        [[ "$_at_tgt" != /* ]] && _at_tgt="$_at_dir/$_at_tgt"
        _at_src="$_at_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_at_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _at_src _at_dir _at_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _at_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_at_home" && -d "$_at_home" && "$HOME" != "$_at_home" ]]; then
        export HOME="$_at_home"
    fi
    unset _at_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=${IMSISTING_ROOT:-/tmp}/tmp}"

# The PLMN register, when it has been downloaded. Same source the cell survey
# reads, so a modem survey and a radio survey cannot disagree about who owns a
# network — and both go silent together when nobody ran the fetcher.
if [[ -r "${IMSISTING_ROOT}/tools/lib/refdata.sh" ]]; then
    # shellcheck source=tools/lib/refdata.sh
    source "${IMSISTING_ROOT}/tools/lib/refdata.sh"
fi

# ── small utilities ─────────────────────────────────────────────────────
# A TSV cell must not carry a tab or a newline: one stray byte in a vendor
# response and every downstream column shifts by one.
at_tsv() {
    local s="${1:-}"
    s="${s//$'\t'/ }"; s="${s//$'\n'/ }"; s="${s//$'\r'/ }"
    printf '%s' "$s"
}

at_norm_hex() {
    local h="${1:-}"
    h="${h// /}"; h="${h//:/}"; h="${h//$'\n'/}"; h="${h//$'\r'/}"
    printf '%s' "${h^^}"
}

at_is_hex() {
    local h; h=$(at_norm_hex "${1:-}")
    [[ -n "$h" && "${h//[^0-9A-F]/}" == "$h" && $(( ${#h} % 2 )) -eq 0 ]]
}

# Nibble-swapped packed decimal (TS 23.003 §2.2 / TS 31.102). The low nibble
# of each octet is the first digit; a trailing F is the odd-length pad and is
# dropped, which is why an IMEI of 15 digits arrives as 8 octets.
at_bcd_swap() {
    local h; h=$(at_norm_hex "${1:-}")
    local out="" i
    for (( i = 0; i < ${#h}; i += 2 )); do
        out+="${h:i+1:1}${h:i:1}"
    done
    printf '%s' "${out//F/}"
}

# Luhn over a decimal string. The check digit is the one field an invented
# IMEI usually gets wrong, so it is worth computing rather than trusting.
at_luhn_ok() {
    local n="${1:-}" sum=0 i d alt=0
    [[ "$n" =~ ^[0-9]{2,}$ ]] || return 1
    for (( i = ${#n} - 1; i >= 0; i-- )); do
        d="${n:i:1}"
        if (( alt )); then
            d=$(( d * 2 ))
            (( d > 9 )) && d=$(( d - 9 ))
        fi
        sum=$(( sum + d ))
        alt=$(( ! alt ))
    done
    (( sum % 10 == 0 ))
}

# GSM 7-bit default alphabet, one character (TS 23.038 §6.2.1). Most of the
# table is ASCII; the fourteen exceptions are the ones a naive mapper gets
# wrong, and a wrong SPN is a wrong operator name on a screen.
at_gsm7_char() {  # <septet 0..127>
    local hx
    hx=$(printf '%02X' "$(( ${1:-0} & 0x7F ))")
    case "$hx" in
        00) printf ' ' ;;   01) printf '@' ;;   02) printf '\u00A3' ;;
        03) printf '$' ;;   04) printf '\u00A4' ;; 05) printf '\u00E8' ;;
        06) printf '\u00E9' ;; 07) printf '\u00F9' ;; 08) printf '\u00EC' ;;
        09) printf '\u00F2' ;; 0A) printf '\u00C7' ;; 0B) printf $'\n' ;;
        0C) printf '\u00D8' ;; 0D) printf '\u00F8' ;; 0E) printf '\u00C5' ;;
        0F) printf '\u00E5' ;; 10) printf '\u0394' ;; 11) printf '_' ;;
        12) printf '\u03A6' ;; 13) printf '\u0393' ;; 14) printf '\u039B' ;;
        15) printf '\u03A9' ;; 16) printf '\u03A0' ;; 17) printf '\u03A8' ;;
        18) printf '\u03A3' ;; 19) printf '\u0398' ;; 1A) printf '\u039E' ;;
        1B) printf ' ' ;;   1C) printf '\u00C6' ;; 1D) printf '\u00E6' ;;
        1E) printf '\u00DF' ;; 1F) printf '\u00C9' ;;
        24) printf '\u00A4' ;; 40) printf '\u00A1' ;; 5B) printf '\u00C4' ;;
        5C) printf '\u00D6' ;; 5D) printf '\u00D1' ;; 5E) printf '\u00DC' ;;
        5F) printf '\u00A7' ;; 60) printf '\u00BF' ;; 7B) printf '\u00E4' ;;
        7C) printf '\u00F6' ;; 7D) printf '\u00F1' ;; 7E) printf '\u00FC' ;;
        7F) printf '\u00E0' ;;
        *)  printf "\\$(printf '%03o' "$(( 16#$hx ))")" ;;
    esac
}

# Packed 7-bit unpacking: each character starts at a bit offset that is a
# multiple of seven, so a character straddles two octets roughly half the time.
at_gsm7_unpack() {
    local h; h=$(at_norm_hex "${1:-}")
    [[ -n "$h" ]] || return 1
    local out="" acc=0 bits=0 i b
    for (( i = 0; i < ${#h}; i += 2 )); do
        b=$(( 16#${h:i:2} ))
        acc=$(( acc | (b << bits) ))
        bits=$(( bits + 8 ))
        while (( bits >= 7 )); do
            out+=$(at_gsm7_char $(( acc & 0x7F )))
            acc=$(( acc >> 7 ))
            bits=$(( bits - 7 ))
        done
    done
    printf '%s' "$out"
}

# EF_SPN's alpha identifier is NOT packed: TS 31.102 §4.2.12 stores one 7-bit
# character per octet, padded with 0xFF. Unpacking it would produce a name two
# characters per octet long and entirely wrong, which is the trap this comment
# exists to keep shut.
at_gsm7_unpacked_alpha() {
    local h; h=$(at_norm_hex "${1:-}")
    local out="" i b
    for (( i = 0; i < ${#h}; i += 2 )); do
        b=$(( 16#${h:i:2} & 0x7F ))
        [[ "$b" -eq 0x7F ]] && continue
        out+=$(at_gsm7_char "$b")
    done
    printf '%s' "$out"
}

# ── the port ────────────────────────────────────────────────────────────
# Fake tty. The directory named by MODEM_AT_FAKE holds one file per canned
# response, named by at_fake_key(), plus an optional DEFAULT for anything not
# listed. Writes are recorded in .sent so a test can assert what was built as
# well as what was parsed — the command string is half the finding.
at_fake_key() {
    printf '%s' "${1:-}" | tr -c 'A-Za-z0-9' '_'
}

at_fake_reply() {
    local dir="$MODEM_AT_FAKE" key
    key=$(at_fake_key "${1:-}")
    if [[ -f "$dir/$key" ]]; then
        cat "$dir/$key"
    elif [[ -f "$dir/DEFAULT" ]]; then
        cat "$dir/DEFAULT"
    else
        printf '\r\nERROR\r\n'
    fi
}

# Real tty. Raw 8N1 or the line discipline answers with the command echoed
# back, and a parser that does not know the difference reads its own request
# as the device's reply.
at_exchange() {
    local port="$1" cmd="$2" wait="${3:-1}"
    local fd ch buf="" i ticks
    [[ -c "$port" || -e "$port" ]] || return 1
    if stty -F "$port" 115200 raw -echo -echoe -echok -echoctl \
                -iexten -ixon -crtscts cs8 -parenb -cstopb 2>/dev/null; then
        :
    elif stty -f "$port" 115200 raw -echo 2>/dev/null; then
        :
    else
        return 1
    fi
    exec {fd}<>"$port" 2>/dev/null || return 1
    printf '%s\r' "$cmd" >&"$fd" 2>/dev/null || { exec {fd}>&-; return 1; }
    ticks=$(( wait * 5 ))
    for (( i = 0; i < ticks; i++ )); do
        if IFS= read -r -t 0.2 -n 1 -u "$fd" ch; then
            buf+="$ch"
            case "$buf" in
                *$'OK\r'*|*$'OK\n'*|*$'ERROR\r'*|*$'ERROR\n'*|\
                *'+CME ERROR'*|*'+CMS ERROR'*) break ;;
            esac
        else
            [[ -n "$buf" ]] && break
        fi
    done
    exec {fd}>&-
    printf '%s' "$buf"
}

# The single door every command goes through.
at_cmd() {
    local port="$1" cmd="$2" wait="${3:-1}"
    if [[ -n "${MODEM_AT_FAKE:-}" ]]; then
        [[ -d "$MODEM_AT_FAKE" ]] || { printf 'ERROR\tMODEM_AT_FAKE is not a directory\n' >&2; return 2; }
        printf '%s\n' "$cmd" >> "$MODEM_AT_FAKE/.sent" 2>/dev/null || true
        at_fake_reply "$cmd"
        return 0
    fi
    at_exchange "$port" "$cmd" "$wait"
}

# ── response parsing ────────────────────────────────────────────────────
# The value after "<TAG>" (with or without a colon) on the first line carrying
# it. The colon is optional because a vendor dialect that writes "OK" and one
# that writes "OK:" are both in the field.
at_field() {
    local resp="${1:-}" tag="${2:-}" line val
    [[ -n "$tag" ]] || return 1
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" == *"$tag"* ]] || continue
        val="${line#*"$tag"}"
        [[ "$val" == :* ]] && val="${val#:}"
        val="${val#"${val%%[![:space:]]*}"}"
        printf '%s' "$val"
        return 0
    done <<< "$resp"
    return 1
}

# Every line carrying the tag, one per line. An EF walk needs all of them.
at_field_all() {
    local resp="${1:-}" tag="${2:-}" line val any=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" == *"$tag"* ]] || continue
        val="${line#*"$tag"}"
        [[ "$val" == :* ]] && val="${val#:}"
        val="${val#"${val%%[![:space:]]*}"}"
        printf '%s\n' "$val"
        any=1
    done <<< "$resp"
    (( any ))
}

# A "<key>: <value>" line where two keys share one line, which is how Sierra's
# !GSTATUS writes almost every row ("LTE Rx chan:  1650\t\tLTE Tx chan: 19650").
# The value therefore ends at the next tab or at a run of spaces wide enough to
# be column padding rather than a value, and a naiver split returns
# "165019650" — a number that is not wrong so much as two numbers.
at_kv() {  # <resp> <key>
    local resp="${1:-}" key="${2:-}" line val
    [[ -n "$key" ]] || return 1
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ "$line" == *"$key"* ]] || continue
        val="${line#*"$key"}"
        [[ "$val" == :* ]] && val="${val#:}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%%$'\t'*}"
        val="${val%%  *}"
        val="${val%"${val##*[![:space:]]}"}"
        printf '%s' "$val"
        return 0
    done <<< "$resp"
    return 1
}

# Comma-separated payload into one field per line, quotes removed. Every
# +QENG, +COPS, +CRSM and +CSQ payload in the world is this shape.
at_csv() {
    local s="${1:-}" item
    s="${s//\"/}"
    local -a parts=()
    IFS=',' read -r -a parts <<< "$s"
    for item in "${parts[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        printf '%s\n' "$item"
    done
}

# A response as a list of non-empty lines with CR stripped and the echoed
# command dropped — an echo is not an answer.
at_lines() {
    local resp="${1:-}" echo_cmd="${2:-}" line
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && continue
        [[ -n "$echo_cmd" && "$line" == "$echo_cmd" ]] && continue
        printf '%s\n' "$line"
    done <<< "$resp"
}

# The final result. AT has exactly four: OK, ERROR, +CME ERROR and +CMS ERROR,
# and the last two carry a code that names what the device refused.
at_final() {
    local resp="${1:-}"
    case "$resp" in
        *'+CME ERROR'*)  printf 'cme' ;;
        *'+CMS ERROR'*)  printf 'cms' ;;
        *'ERROR'*)       printf 'error' ;;
        *'OK'*)          printf 'ok' ;;
        *)               printf 'silent' ;;
    esac
}

at_error_code() {
    local resp="${1:-}" c
    c=$(at_field "$resp" '+CME ERROR')
    [[ -n "$c" ]] || c=$(at_field "$resp" '+CMS ERROR')
    printf '%s' "${c:-}"
}

# ── identity decode ─────────────────────────────────────────────────────
# MCCs where the MNC is three digits. Not derivable from the digits and not
# meant to be: TS 23.003 leaves the split to the assignment, which is why EF_AD
# outranks this table and the table outranks the flat 2-digit default.
at_mnc_len_3_mccs() {
    printf '%s\n' 302 310 311 312 313 314 315 316 334 405 708 722 732
}

at_mnc_len_default() {  # <mcc> -> 2|3
    local mcc="${1:-}" m
    while IFS= read -r m; do
        [[ "$mcc" == "$m" ]] && { printf '3'; return 0; }
    done < <(at_mnc_len_3_mccs)
    printf '2'
}

# at_imsi_split <imsi> [mnc_len] -> mcc<TAB>mnc<TAB>msin<TAB>confidence
at_imsi_split() {
    local imsi="${1:-}" want="${2:-}" mcc mnc_len conf msin
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || return 1
    mcc="${imsi:0:3}"
    if [[ -n "$want" ]]; then
        mnc_len="$want"; conf="EF_AD"
    else
        mnc_len=$(at_mnc_len_default "$mcc")
        if [[ "$(at_mnc_len_3_mccs | grep -cx "$mcc")" == "1" ]]; then
            conf="table"
        else
            conf="default-2"
        fi
    fi
    [[ "$mnc_len" == "2" || "$mnc_len" == "3" ]] || { mnc_len="2"; conf="default-2"; }
    (( ${#imsi} > 3 + mnc_len )) || return 1
    mnc="${imsi:3:mnc_len}"
    msin="${imsi:3+mnc_len}"
    printf '%s\t%s\t%s\t%s' "$mcc" "$mnc" "$msin" "$conf"
}

# EF_AD byte 4 low nibble is the MNC length in digits (TS 31.102 §4.2.18).
at_efad_mnc_len() {  # <efad-hex> -> 2|3 (empty when the byte is absent)
    local h; h=$(at_norm_hex "${1:-}")
    [[ ${#h} -ge 8 ]] || return 1
    local b=$(( 16#${h:6:2} & 0x0F ))
    case "$b" in
        2|3) printf '%s' "$b" ;;
        *)   return 1 ;;
    esac
}

# ── status words ────────────────────────────────────────────────────────
# ISO 7816-4. A CRSM that answers 6A82 is not a failure of the module, it is
# the card saying the file is not there, and those are different answers.
#
# The two arguments are the DECIMAL bytes the card sent, because that is what
# +CRSM reports: "144,0" is 0x90 0x00. Converting here rather than at every
# call site keeps one spelling of a status word in the whole module.
at_sw_name() {  # <sw1-dec> <sw2-dec>
    local hex
    [[ "${1:-}" =~ ^[0-9]+$ ]] || { printf 'no status word'; return 0; }
    hex=$(printf '%02X%02X' "$(( ${1:-0} & 0xFF ))" "$(( ${2:-0} & 0xFF ))")
    at_sw_hex_name "$hex"
}

at_sw_hex_name() {  # <4 hex digits>
    local hex="${1:-0000}"
    case "$hex" in
        9000)   printf 'success' ;;
        6200|6282) printf 'success, warning: %s' "$hex" ;;
        6A82)   printf 'file or application not found' ;;
        6A86)   printf 'incorrect P1/P2 parameters' ;;
        6A87)   printf 'incorrect P3 length' ;;
        6982)   printf 'security status not satisfied' ;;
        6985)   printf 'conditions of use not satisfied' ;;
        6983)   printf 'authentication method blocked (PIN)' ;;
        6984)   printf 'referenced data invalidated' ;;
        6A83)   printf 'record not found' ;;
        6A88)   printf 'referenced data not found' ;;
        6700)   printf 'wrong length' ;;
        6D00)   printf 'instruction not supported' ;;
        6E00)   printf 'class not supported' ;;
        6F00)   printf 'no precise diagnosis' ;;
        63C*)   printf 'verification failed, %d attempt(s) left' "$(( 16#${hex:3:1} ))" ;;
        63*)    printf 'verification failed' ;;
        *)      printf 'unrecognised status word %s' "$hex" ;;
    esac
}

# +CME / +CMS error codes that an AT surface actually hits (TS 27.007 §9.2,
# TS 27.005 §3.2.5). Unlisted codes are reported by number, never guessed.
at_cme_name() {
    case "${1:-}" in
        3)    printf 'operation not allowed' ;;
        4)    printf 'operation not supported' ;;
        5)    printf 'PH-SIM PIN required' ;;
        10)   printf 'SIM not inserted' ;;
        11)   printf 'SIM PIN required' ;;
        12)   printf 'SIM PUK required' ;;
        13)   printf 'SIM failure' ;;
        14)   printf 'SIM busy' ;;
        15)   printf 'SIM wrong' ;;
        16)   printf 'incorrect password' ;;
        17)   printf 'SIM PIN2 required' ;;
        18)   printf 'SIM PUK2 required' ;;
        20)   printf 'memory full' ;;
        22)   printf 'not found' ;;
        30)   printf 'no network service' ;;
        32)   printf 'network not allowed — emergency calls only' ;;
        50)   printf 'incorrect parameters' ;;
        58)   printf 'unsupported command' ;;
        100)  printf 'unknown' ;;
        103)  printf 'illegal MS' ;;
        106)  printf 'illegal ME' ;;
        107)  printf 'GPRS services not allowed' ;;
        111)  printf 'PLMN not allowed' ;;
        112)  printf 'location area not allowed' ;;
        113)  printf 'roaming not allowed in this location area' ;;
        *)    printf 'code %s' "${1:-?}" ;;
    esac
}

# ── RAT / frequency ─────────────────────────────────────────────────────
# TS 27.007 §7.3 <AcT> in +COPS. One number that decides the generation, so it
# gets a table rather than an if-chain in each caller.
at_act_name() {
    case "${1:-}" in
        0) printf 'GSM' ;;   1) printf 'GSM Compact' ;;
        2) printf 'UTRAN' ;; 3) printf 'GSM/EGPRS' ;;
        4) printf 'UTRAN/HSDPA' ;; 5) printf 'UTRAN/HSDPA' ;;
        6) printf 'UTRAN/HSDPA/HSUPA' ;; 7) printf 'E-UTRAN (LTE)' ;;
        8) printf 'EC-GSM-IoT' ;; 9) printf 'NR (5G)' ;;
        10) printf 'E-UTRA-NR dual connectivity' ;;
        *) printf 'unknown (%s)' "${1:-}" ;;
    esac
}

at_act_gen() {
    case "${1:-}" in
        0|8) printf '2G' ;;
        1|2|3|4|5|6) printf '3G' ;;
        7|10) printf '4G' ;;
        9) printf '5G' ;;
        *) printf 'unknown' ;;
    esac
}

# LTE EARFCN -> downlink MHz (TS 36.101 Table 5.7.3-1), the same band window
# arithmetic 02_cell_recon applies, restated so the two cannot drift into
# different answers for the same number.
at_lte_earfcn_mhz() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$n" 'BEGIN{
        split("1 2110 0 0 599|2 1930 600 600 1199|3 1805 1200 1200 1949|" \
              "4 2110 1950 1950 2399|5 869 2400 2400 2649|7 2620 2750 2750 3449|" \
              "8 925 3450 3450 3799|20 791 6150 6150 6449|28 758 9210 9210 9659|" \
              "38 2570 37750 37750 38249|40 2300 38650 38650 39649|41 2496 39650 39650 41589",
              b, "|")
        for (i = 1; i <= length(b); i++) {
            split(b[i], f, " ")
            if (n >= f[4] && n <= f[5]) { printf "%.1f", f[2] + 0.1*(n - f[3]); exit }
        }
        exit 1
    }'
}

# NR-ARFCN -> MHz (TS 38.104 Table 5.4.2.1-1). The raster is piecewise; 5 kHz
# everywhere is right at a band edge and wrong by up to 300 MHz inside n77.
at_nr_arfcn_mhz() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$n" 'BEGIN{
        if      (n <= 599999)  printf "%.3f", 0        + 0.005 * n
        else if (n <= 2016666) printf "%.3f", 3000     + 0.015 * (n - 600000)
        else if (n <= 3279165) printf "%.3f", 24250.08 + 0.060 * (n - 2016667)
        else exit 1
    }'
}

# +CSQ <rssi> -> dBm. 99 is the "unknown" sentinel and must not become -113.
at_csq_dbm() {
    local r="${1:-}"
    [[ "$r" =~ ^[0-9]+$ ]] || { printf 'not-advertised'; return 0; }
    (( r == 99 )) && { printf 'not-advertised'; return 0; }
    (( r > 31 )) && r=31
    printf '%s' "$(( -113 + 2 * r ))"
}

# ── PLMN name through the shared register ───────────────────────────────
# Three states, never collapsed: a found operator, an absent assignment, and a
# register nobody downloaded. The third is unobserved, which is not "unknown".
at_plmn_lookup() {  # <mcc> <mnc> -> operator<TAB>country<TAB>state
    local mcc="${1:-}" mnc="${2:-}" out state rest op country
    if declare -F refdata_plmn >/dev/null 2>&1; then
        out=$(refdata_plmn "$mcc" "$mnc")
        state="${out%%$'\t'*}"
        rest="${out#*$'\t'}"
        op="${rest%%$'\t'*}"
        country="${rest#*$'\t'}"
        case "$state" in
            ok)     printf '%s\t%s\tmeasured' "$op" "$country" ;;
            absent) printf 'unknown\tunknown\tabsent' ;;
            *)      printf 'unknown\tunknown\tsilent' ;;
        esac
        return 0
    fi
    printf 'unknown\tunknown\tsilent'
}

# ── --at-surface ────────────────────────────────────────────────────────
# The ports a modem exposes, read from sysfs rather than guessed from a name.
# A ttyUSB is not automatically an AT port: on a Quectel EC25 interface 0 is
# the DM port, 1 is NMEA, 2 and 3 are AT, and 4 is QMI. The interface number is
# the only thing that tells them apart, so it is read and reported.
at_sysfs_attr() {  # <tty-name> <attr>
    local d="/sys/class/tty/$1/device" i
    for (( i = 0; i < 7; i++ )); do
        [[ -r "$d/$2" ]] && { cat "$d/$2" 2>/dev/null | head -1; return 0; }
        d="$d/.."
    done
    return 1
}

at_usb_interface() {  # <tty-name> -> interface number
    local p
    p=$(readlink -f "/sys/class/tty/$1/device" 2>/dev/null) || return 1
    [[ "$p" =~ :1\.([0-9]+) ]] && printf '%s' "${BASH_REMATCH[1]}"
}

at_vendor_family() {
    case "${1,,}" in
        12d1) printf 'Huawei' ;;
        19d2) printf 'ZTE' ;;
        2c7c) printf 'Quectel' ;;
        1199) printf 'Sierra Wireless' ;;
        1bc7) printf 'Telit' ;;
        1e0e) printf 'SIMCom' ;;
        1546) printf 'u-blox' ;;
        1e2d) printf 'Thales/Cinterion' ;;
        0421) printf 'Nokia' ;;
        0bdb) printf 'Ericsson' ;;
        0af0) printf 'Option' ;;
        *)    printf 'unrecognised' ;;
    esac
}

# The interface number as a role, for the vendors whose layout is published.
# Unknown layouts get `unknown` rather than a guess, because a wrong AT port
# sends a command into a DM stream and reads the reply as garbage.
at_iface_role() {  # <family> <ifnum>
    local fam="${1:-}" n="${2:-}"
    case "$fam:$n" in
        Quectel:0|SIMCom:0) printf 'dm/diag' ;;
        Quectel:1|SIMCom:1) printf 'nmea' ;;
        Quectel:2|Quectel:3|SIMCom:2|SIMCom:3) printf 'at' ;;
        Quectel:4|SIMCom:4) printf 'qmi' ;;
        Huawei:0) printf 'at' ;;
        Huawei:1|Huawei:2) printf 'at' ;;
        Sierra*:0) printf 'at' ;;
        Telit:0|Telit:1|Telit:2|Telit:3) printf 'at' ;;
        *) printf 'unknown' ;;
    esac
}

at_surface() {
    local probe=0
    [[ "${1:-}" == "probe" ]] && probe=1
    printf 'port\tkind\tvendor\tproduct\tfamily\tinterface\trole\tanswer\n'
    local base name tty vendor product fam iface role ans
    for base in /sys/class/tty/ttyUSB* /sys/class/tty/ttyACM* \
                /sys/class/tty/wwan* /dev/cdc-wdm*; do
        [[ -e "$base" ]] || continue
        name="${base##*/}"
        if [[ "$base" == /dev/* ]]; then
            tty="${name}"
        else
            tty="${name}"
        fi
        vendor=$(at_sysfs_attr "$tty" idVendor || true)
        product=$(at_sysfs_attr "$tty" idProduct || true)
        fam=$(at_vendor_family "${vendor:-0000}")
        iface=$(at_usb_interface "$tty" || true)
        role="unknown"
        [[ -n "${iface:-}" ]] && role=$(at_iface_role "$fam" "$iface")
        ans="not-probed"
        if (( probe )); then
            case "$tty" in
                wwan*|cdc-wdm*)
                    # A wwan or cdc-wdm node is not a line-oriented AT port;
                    # QMI and MBIM have their own framing and their own module.
                    ans="not-a-tty" ;;
                *)
                    local resp
                    resp=$(at_cmd "/dev/$tty" 'ATI' 1 2>/dev/null || true)
                    case "$(at_final "$resp")" in
                        ok)      ans="answered ATI" ;;
                        error)   ans="answered ERROR" ;;
                        cme|cms) ans="answered $(at_final "$resp"): $(at_error_code "$resp")" ;;
                        *)       ans="silent" ;;
                    esac ;;
            esac
        fi
        printf '/dev/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(at_tsv "$tty")" \
            "$([[ "$tty" == wwan* || "$tty" == cdc-wdm* ]] && printf 'qmi/mbim' || printf 'serial')" \
            "$(at_tsv "${vendor:-}")" "$(at_tsv "${product:-}")" \
            "$(at_tsv "$fam")" "$(at_tsv "${iface:-}")" \
            "$(at_tsv "$role")" "$(at_tsv "$ans")"
    done
    return 0
}

# ── --at-session ────────────────────────────────────────────────────────
# The device page. What it is, what firmware it runs, and whose subscription
# is in it — all of it second-hand, all of it marked as the device's claim.
at_session() {
    local port="${1:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }

    local ati imei imsi iccid cgmi cgmm cgmr cpin ws46 cops creg csq
    ati=$(at_cmd "$port" 'ATI' 1)
    cgmi=$(at_cmd "$port" 'AT+CGMI' 1)
    cgmm=$(at_cmd "$port" 'AT+CGMM' 1)
    cgmr=$(at_cmd "$port" 'AT+CGMR' 1)
    imei=$(at_cmd "$port" 'AT+CGSN' 1)
    imsi=$(at_cmd "$port" 'AT+CIMI' 1)
    iccid=$(at_cmd "$port" 'AT+CCID' 1)
    cpin=$(at_cmd "$port" 'AT+CPIN?' 1)
    ws46=$(at_cmd "$port" 'AT+WS46?' 1)
    cops=$(at_cmd "$port" 'AT+COPS?' 1)
    creg=$(at_cmd "$port" 'AT+CREG?' 1)
    csq=$(at_cmd "$port" 'AT+CSQ' 1)

    local v
    printf 'field\tvalue\n'
    printf 'port\t%s\n' "$(at_tsv "$port")"
    v=$(at_field "$ati" 'Revision') || v=""
    [[ -n "$v" ]] && printf 'ati_revision\t%s\n' "$(at_tsv "$v")"
    v=$(at_lines "$ati" 'ATI' | grep -v '^OK$' | head -1) || v=""
    [[ -n "$v" ]] && printf 'ati_model\t%s\n' "$(at_tsv "$v")"

    v=$(at_lines "$cgmi" '' | grep -v '^OK$' | head -1) || v=""
    printf 'manufacturer\t%s\n' "$(at_tsv "${v:-not-advertised}")"
    v=$(at_lines "$cgmm" '' | grep -v '^OK$' | head -1) || v=""
    printf 'model\t%s\n' "$(at_tsv "${v:-not-advertised}")"
    v=$(at_lines "$cgmr" '' | grep -v '^OK$' | head -1) || v=""
    printf 'firmware\t%s\n' "$(at_tsv "${v:-not-advertised}")"

    # The serial number, and the two things that are worth computing from it:
    # the Type Allocation Code (first eight digits, of which the first two are
    # the reporting body) and whether the check digit is a real one.
    v=$(at_lines "$imei" '' | grep -vE '^(OK|ERROR|\+CME|\+CMS)' | head -1) || v=""
    if [[ "$v" =~ ^[0-9]{14,16}$ ]]; then
        printf 'imei\t%s\n' "$v"
        printf 'imei_tac\t%s\n' "${v:0:8}"
        printf 'imei_reporting_body\t%s\n' "${v:0:2}"
        printf 'imei_luhn\t%s\n' "$(at_luhn_ok "$v" && printf 'valid' || printf 'invalid')"
    else
        printf 'imei\t%s\n' "$(at_tsv "${v:-not-advertised}")"
    fi

    v=$(at_lines "$imsi" '' | grep -vE '^(OK|ERROR|\+CME|\+CMS)' | head -1) || v=""
    if [[ "$v" =~ ^[0-9]{6,15}$ ]]; then
        printf 'imsi\t%s\n' "$v"
        local split mcc mnc msin conf
        split=$(at_imsi_split "$v") && {
            IFS=$'\t' read -r mcc mnc msin conf <<< "$split"
            printf 'imsi_mcc\t%s\n' "$mcc"
            printf 'imsi_mnc\t%s\n' "$mnc"
            printf 'imsi_msin\t%s\n' "$msin"
            printf 'imsi_mnc_len_source\t%s\n' "$conf"
            local named
            named=$(at_plmn_lookup "$mcc" "$mnc")
            printf 'home_operator\t%s\n' "$(at_tsv "${named%%$'\t'*}")"
            printf 'home_country\t%s\n' "$(at_tsv "$(printf '%s' "$named" | cut -f2)")"
            printf 'home_operator_state\t%s\n' "$(printf '%s' "$named" | cut -f3)"
        }
    else
        printf 'imsi\t%s\n' "$(at_tsv "${v:-not-advertised}")"
    fi

    v=$(at_lines "$iccid" '' | grep -vE '^(OK|ERROR|\+CME|\+CMS)' | head -1) || v=""
    printf 'iccid\t%s\n' "$(at_tsv "${v:-not-advertised}")"
    if [[ "$v" =~ ^[0-9]{18,20}$ ]]; then
        printf 'iccid_luhn\t%s\n' "$(at_luhn_ok "$v" && printf 'valid' || printf 'invalid')"
    fi

    v=$(at_field "$cpin" '+CPIN') || v=""
    printf 'sim_state\t%s\n' "$(at_tsv "${v:-not-advertised}")"

    v=$(at_field "$ws46" '+WS46') || v=""
    printf 'supported_rats\t%s\n' "$(at_tsv "${v:-not-advertised}")"

    # The registered network, which is a different fact from the home network:
    # a roaming SIM is on somebody else's PLMN and +CIMI does not say so.
    v=$(at_field "$cops" '+COPS') || v=""
    if [[ -n "$v" ]]; then
        local -a f=()
        mapfile -t f < <(at_csv "$v")
        printf 'cops_mode\t%s\n' "${f[0]:-}"
        printf 'registered_operator\t%s\n' "$(at_tsv "${f[2]:-not-advertised}")"
        printf 'registered_act\t%s\n' "$(at_act_name "${f[3]:-}")"
        printf 'registered_gen\t%s\n' "$(at_act_gen "${f[3]:-}")"
    else
        printf 'registered_operator\tnot-advertised\n'
    fi

    v=$(at_field "$creg" '+CREG') || v=""
    if [[ -n "$v" ]]; then
        local -a f=()
        mapfile -t f < <(at_csv "$v")
        printf 'creg_status\t%s\n' "${f[1]:-not-advertised}"
    fi
    v=$(at_field "$csq" '+CSQ') || v=""
    if [[ -n "$v" ]]; then
        local -a f=()
        mapfile -t f < <(at_csv "$v")
        printf 'rssi_dbm\t%s\n' "$(at_csq_dbm "${f[0]:-99}")"
        printf 'csq_raw\t%s\n' "$(at_tsv "${f[0]:-}")"
    fi
    printf 'source\tdevice (every row above is what the modem claims)\n'
    return 0
}

# ── --at-eng ────────────────────────────────────────────────────────────
# A cell row in exactly the sixteen columns 02_cell_recon writes. `cipher` is
# not-advertised on every vendor grammar here: AT has no field that reports the
# cipher in use, and a survey row that silently zeroes it would read as
# "cleartext" rather than "not asked".
at_cell_row() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" \
        "${10}" "${11}" "${12}" "${13}" "${14}" "${15}" "${16}"
}

at_cell_header() {
    printf 'rat\tgen\tarfcn\tfreq_mhz\tplmn\tmcc\tmnc\toperator\tcountry\tcell_id\ttac_lac\tband\trsrp_dbm\tcipher\tsource\tts\n'
}

at_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# One cell row from the pieces every vendor supplies in some order.
#   rat gen arfcn mcc mnc cell_id tac band rsrp source
at_emit_cell() {
    local rat="$1" gen="$2" arfcn="$3" mcc="$4" mnc="$5" cell_id="$6" \
          tac="$7" band="$8" rsrp="$9" source="${10}"
    local freq='not-advertised' plmn operator country state named
    case "$gen" in
        4G) [[ "$arfcn" =~ ^[0-9]+$ ]] && freq=$(at_lte_earfcn_mhz "$arfcn" || printf 'not-advertised') ;;
        5G) [[ "$arfcn" =~ ^[0-9]+$ ]] && freq=$(at_nr_arfcn_mhz "$arfcn" || printf 'not-advertised') ;;
    esac
    if [[ -n "$mcc" && -n "$mnc" ]]; then
        plmn="$mcc-$mnc"
        named=$(at_plmn_lookup "$mcc" "$mnc")
        operator="${named%%$'\t'*}"
        country=$(printf '%s' "$named" | cut -f2)
        state=$(printf '%s' "$named" | cut -f3)
    else
        plmn='not-advertised'; operator='unknown'; country='unknown'; state='silent'
    fi
    at_cell_row "$(at_tsv "$rat")" "$(at_tsv "$gen")" \
        "$(at_tsv "${arfcn:-not-advertised}")" "$(at_tsv "$freq")" \
        "$(at_tsv "${plmn:-not-advertised}")" "$(at_tsv "${mcc:-not-advertised}")" \
        "$(at_tsv "${mnc:-not-advertised}")" "$(at_tsv "$operator")" \
        "$(at_tsv "$country")" "$(at_tsv "${cell_id:-not-advertised}")" \
        "$(at_tsv "${tac:-not-advertised}")" "$(at_tsv "${band:-not-advertised}")" \
        "$(at_tsv "${rsrp:-not-advertised}")" 'not-advertised' \
        "$(at_tsv "$source")" "$(at_now)"
}

# Quectel +QENG="servingcell". The field order is fixed by the vendor for each
# RAT and differs between them, which is why the RAT token is read first.
at_eng_quectel_serving() {  # <payload> -> cell row, or exit 1
    local payload="$1"
    local -a f=()
    mapfile -t f < <(at_csv "$payload")
    (( ${#f[@]} >= 4 )) || return 1
    # f[0] is the response's own name ("servingcell" / "neighbourcell") and is
    # not cell data. The LTE page then carries a <state> field before the RAT;
    # the NR5G page does not, which is why the RAT is looked for at both
    # offsets rather than at the one the LTE grammar trained us to expect.
    local rat="${f[1]}"
    case "$rat" in
        LTE|NR5G-SA|NR5G-NSA|WCDMA|GSM|CDMA) : ;;
        *) rat="${f[2]}" ;;
    esac
    case "$rat" in
        LTE)
            # state, LTE, is_tdd, mcc, mnc, cellid, pcid, earfcn, band,
            # ul_bw, dl_bw, tac, rsrp, rsrq, rssi, sinr
            (( ${#f[@]} >= 17 )) || return 1
            at_emit_cell 'LTE' '4G' "${f[8]}" "${f[4]}" "${f[5]}" \
                "${f[6]}" "${f[12]}" "${f[9]}" "${f[13]}" 'quectel-qeng' ;;
        NR5G-SA|NR5G-NSA)
            # duplex, mcc, mnc, cellid, pcid, tac, arfcn, band, dl_bw, rsrp,
            # rsrq, sinr, scs, srxlev
            (( ${#f[@]} >= 12 )) || return 1
            at_emit_cell '5G NR' '5G' "${f[8]}" "${f[3]}" "${f[4]}" \
                "${f[5]}" "${f[7]}" "${f[9]}" "${f[11]}" 'quectel-qeng' ;;
        *)
            # The WCDMA and GSM pages use a different field order per firmware
            # revision and no published table pins them. Decoding either by
            # guess would put a plausible number in a column that means
            # something else, so this refuses and --at-eng falls through to
            # +COPS/+CSQ, which reports the operator and the generation and
            # leaves the cell fields not-advertised. --at-parse still shows the
            # raw payload for anyone who wants to decode it by hand.
            return 1 ;;
    esac
}

# Sierra AT!GSTATUS? is a block of key/value lines, not a CSV.
at_eng_sierra() {  # <response> -> cell row, or exit 1
    local resp="$1" system band chan rsrp rsrq sinr mcc mnc tac
    system=$(at_kv "$resp" 'System mode') || return 1
    band=$(at_kv "$resp" 'LTE band') || band=""
    chan=$(at_kv "$resp" 'LTE Rx chan') || chan=""
    rsrp=$(at_kv "$resp" 'PCC RxM RSRP') || rsrp=""
    rsrq=$(at_kv "$resp" 'PCC RxM RSRQ') || rsrq=""
    sinr=$(at_kv "$resp" 'PCC RxM SINR') || sinr=""
    mcc=$(at_kv "$resp" 'MCC:') || mcc=""
    mnc=$(at_kv "$resp" 'MNC:') || mnc=""
    tac=$(at_kv "$resp" 'TAC:') || tac=""
    case "$system" in
        *LTE*) at_emit_cell 'LTE' '4G' "${chan//[^0-9]/}" "$mcc" "$mnc" '' "$tac" \
                   "${band//[^A-Za-z0-9]/}" "${rsrp//[^0-9-]/}" 'sierra-gstatus' ;;
        *NR5G*|*5G*) at_emit_cell '5G NR' '5G' "${chan//[^0-9]/}" "$mcc" "$mnc" '' "$tac" \
                   "${band//[^A-Za-z0-9]/}" "${rsrp//[^0-9-]/}" 'sierra-gstatus' ;;
        *) return 1 ;;
    esac
}

# Huawei ^SYSINFO. sys_mode names the RAT; the band and channel need
# ^SYSINFOEX, so they are reported as not-advertised rather than invented.
at_eng_huawei() {  # <response> -> cell row, or exit 1
    local resp="$1" val
    local -a f=()
    val=$(at_field "$resp" '^SYSINFO') || return 1
    mapfile -t f < <(at_csv "$val")
    local mode="${f[3]:-}" rat gen
    case "$mode" in
        1|2|3)        rat='GSM'; gen='2G' ;;
        4|5|6|7|9)    rat='UMTS'; gen='3G' ;;
        10|11|12|13)  rat='LTE'; gen='4G' ;;
        14|15|16)     rat='CDMA'; gen='3G' ;;
        *)            return 1 ;;
    esac
    at_emit_cell "$rat" "$gen" '' '' '' '' '' '' '' 'huawei-sysinfo'
}

# +QNWINFO: "FDD LTE","46000","LTE BAND 3",1650 — the most portable of the
# vendor pages, so it is tried first and used to fill the gaps the others leave.
at_eng_qnwin() {  # <response> -> rat<TAB>plmn<TAB>band<TAB>arfcn, or exit 1
    local resp="$1" val
    local -a f=()
    val=$(at_field "$resp" '+QNWINFO') || return 1
    mapfile -t f < <(at_csv "$val")
    (( ${#f[@]} >= 4 )) || return 1
    local plmn="${f[1]}" mcc="" mnc="" band="" chan="${f[3]}"
    band=$(printf '%s' "${f[2]}" | tr -cd 'A-Za-z0-9 ')
    band="${band##* }"
    if [[ "$plmn" =~ ^([0-9]{3})([0-9]{2,3})$ ]]; then
        mcc="${BASH_REMATCH[1]}"; mnc="${BASH_REMATCH[2]}"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${f[0]}" "$mcc" "$mnc" "${band:-}" \
        "${chan//[^0-9]/}" "${f[2]}"
}

at_eng() {
    local port="${1:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }

    local qnwin qeng gstat sysinfo cops csq
    qnwin=$(at_cmd "$port" 'AT+QNWINFO' 1) || qnwin=""
    qeng=$(at_cmd "$port" 'AT+QENG="servingcell"' 1) || qeng=""
    gstat=$(at_cmd "$port" 'AT!GSTATUS?' 1) || gstat=""
    sysinfo=$(at_cmd "$port" 'AT^SYSINFO' 1) || sysinfo=""
    cops=$(at_cmd "$port" 'AT+COPS?' 1) || cops=""
    csq=$(at_cmd "$port" 'AT+CSQ' 1) || csq=""

    at_cell_header

    local row="" qn -a qf=()
    if qn=$(at_eng_qnwin "$qnwin" 2>/dev/null); then
        IFS=$'\t' read -r -a qf <<< "$qn"
        local rat="${qf[0]}" mcc="${qf[1]}" mnc="${qf[2]}" band="${qf[3]}" chan="${qf[4]}"
        local gen='unknown'
        case "$rat" in
            *LTE*)  gen='4G'; rat='LTE' ;;
            *NR5G*|*"5G NR"*) gen='5G'; rat='5G NR' ;;
            *WCDMA*|*HSPA*|*UMTS*) gen='3G'; rat='UMTS' ;;
            *GSM*|*EDGE*|*GPRS*) gen='2G'; rat='GSM' ;;
        esac
        row=$(at_emit_cell "$rat" "$gen" "$chan" "$mcc" "$mnc" '' '' "$band" '' 'quectel-qnwin')
        printf '%s\n' "$row"
    fi

    # A full serving-cell page beats the summary fields, so when it answers it
    # is emitted as well and the summary row above stays as the cross-check.
    if row=$(at_eng_quectel_serving "$(at_field "$qeng" '+QENG' || true)" 2>/dev/null); then
        printf '%s\n' "$row"
    elif row=$(at_eng_sierra "$gstat" 2>/dev/null); then
        printf '%s\n' "$row"
    elif row=$(at_eng_huawei "$sysinfo" 2>/dev/null); then
        printf '%s\n' "$row"
    elif [[ -z "$qn" ]]; then
        # Nothing vendor-side answered. The standard +COPS is all that is left,
        # and it names the operator without naming the cell — which is a real
        # answer, reported as one.
        local val
        local -a f=()
        val=$(at_field "$cops" '+COPS') || val=""
        if [[ -n "$val" ]]; then
            mapfile -t f < <(at_csv "$val")
            local plmnnum="${f[1]}" mcc="" mnc=""
            if [[ "$plmnnum" =~ ^([0-9]{3})([0-9]{2,3})$ ]]; then
                mcc="${BASH_REMATCH[1]}"; mnc="${BASH_REMATCH[2]}"
            fi
            local rsrp=""
            val=$(at_field "$csq" '+CSQ') || val=""
            if [[ -n "$val" ]]; then
                mapfile -t f < <(at_csv "$val")
                rsrp=$(at_csq_dbm "${f[0]:-99}")
            fi
            at_emit_cell "$(at_act_name "${f[3]:-}")" "$(at_act_gen "${f[3]:-}")" \
                '' "$mcc" "$mnc" '' '' '' "$rsrp" 'cops+csq (no engineering page)'
        else
            printf 'ERROR\tno engineering page and no registered network\n' >&2
            return 1
        fi
    fi
    return 0
}

# ── --at-parse ──────────────────────────────────────────────────────────
# A transcript somebody already saved, decoded with the same parsers a live
# session uses. This is the arm that works on a laptop with no modem attached,
# and it is what makes a pasted +QENG page worth keeping.
# A saved transcript puts the command on one line and the answer on the next, so
# a same-line tag lookup finds the command and misses the value. This reads the
# payload on the tag line when there is one and otherwise takes the next line
# that is neither blank nor a result code nor another command.
at_transcript_field() {  # <text> <tag>
    local tag="${2:-}" line v
    [[ -n "$tag" ]] || return 1
    local -a L=()
    mapfile -t L <<< "${1:-}"
    local n=${#L[@]} i=0 j=0
    for (( i = 0; i < n; i++ )); do
        line="${L[i]%$'\r'}"
        [[ "$line" == *"$tag"* ]] || continue
        v="${line#*"$tag"}"
        [[ "$v" == :* ]] && v="${v#:}"
        v="${v#"${v%%[![:space:]]*}"}"
        v="${v%"${v##*[![:space:]]}"}"
        if [[ -n "$v" ]]; then printf '%s' "$v"; return 0; fi
        for (( j = i + 1; j < n; j++ )); do
            v="${L[j]%$'\r'}"
            v="${v#"${v%%[![:space:]]*}"}"
            v="${v%"${v##*[![:space:]]}"}"
            [[ -z "$v" ]] && continue
            case "$v" in
                OK|ERROR|'+CME ERROR'*|'+CMS ERROR'*|AT*) return 1 ;;
            esac
            printf '%s' "$v"; return 0
        done
        return 1
    done
    return 1
}

at_parse_stream() {
    local src="${1:-}" text=""
    if [[ -n "$src" && -f "$src" ]]; then
        text=$(cat "$src")
    elif [[ -n "$src" && "$src" != "-" ]]; then
        text="$src"
    else
        text=$(cat)
    fi
    printf 'field\tvalue\n'
    local v
    while IFS= read -r tag; do
        v=$(at_transcript_field "$text" "$tag") || continue
        printf '%s\t%s\n' "$(at_tsv "$tag")" "$(at_tsv "$v")"
    done <<'TAGS'
+CGSN
+CIMI
+CCID
+CGMI
+CGMM
+CGMR
+CPIN
+COPS
+CREG
+CEREG
+CSQ
+WS46
+QNWINFO
+QENG
^SYSINFO
TAGS
    if [[ "$text" == *'!GSTATUS'* ]]; then
        printf 'gstatus_present\tyes\n'
        while IFS= read -r k; do
            v=$(at_kv "$text" "$k") || continue
            printf 'gstatus_%s\t%s\n' "$(printf '%s' "$k" | tr 'A-Z ' 'a-z_')" "$(at_tsv "$v")"
        done <<'GK'
System mode
LTE band
LTE bw
LTE Rx chan
PCC RxM RSSI
PCC RxM RSRP
PCC RxM RSRQ
PCC RxM SINR
EMM state
GK
    fi
    # A CRSM read is a pair: the command names the file, the answer carries the
    # bytes. Pairing them in the transcript is what makes it evidence — an
    # unpaired hex string says nothing about which EF it came from.
    local line last_cmd="" i=0
    local -a L=()
    mapfile -t L <<< "$text"
    for line in "${L[@]}"; do
        line="${line%$'\r'}"
        case "$line" in
            AT+CRSM=*)
                last_cmd="${line#AT+CRSM=}"
                printf 'crsm_cmd_%d\t%s\n' "$i" "$(at_tsv "$last_cmd")" ;;
            '+CRSM:'*)
                v="${line#*+CRSM:}"
                v="${v#"${v%%[![:space:]]*}"}"
                printf 'crsm_resp_%d\t%s\n' "$i" "$(at_tsv "$v")"
                local -a g=()
                mapfile -t g < <(at_csv "$v")
                printf 'crsm_%d_status\t%s\n' "$i" \
                    "$(at_sw_name "${g[0]:-}" "${g[1]:-}")"
                i=$(( i + 1 )) ;;
        esac
    done
    return 0
}

# ── --at-sim ────────────────────────────────────────────────────────────
# The EF walk. AT+CRSM is the restricted form (named file, three bytes of
# header, no arbitrary APDU); AT+CSIM is the generic form and takes any APDU.
# Both are here because both are on the device and pretending one is enough is
# how a card gets called "unreadable" when it was merely asked the wrong way.
at_ef_table() {
    # name | file id hex | path | read length | decoder
    cat <<'EFS'
EF_ICCID	2FE2	3F00	10	iccid
EF_IMSI	6F07	3F007FFF	9	imsi
EF_AD	6FAD	3F007FFF	4	efad
EF_SPN	6F46	3F007FFF	17	spn
EF_LI	6F05	3F007FFF	2	hex
EF_HPPLMN	6F31	3F007FFF	1	hex
EF_IST	6F7E	3F007FFF	1	hex
EFS
}

# AT+CRSM=176,<fileid>,0,0,<len>,"<path>". 176 is READ BINARY; a record-oriented
# file needs 178 (READ RECORD), which is why the command is a parameter.
at_crsm_read() {  # <port> <fileid-hex> <path> <len> [cmd]
    local port="$1" fid="$2" path="$3" len="$4" cmd="${5:-176}"
    local dec=$(( 16#$fid ))
    at_cmd "$port" "AT+CRSM=$cmd,$dec,0,0,$len,\"$path\"" 2
}

# Split a +CRSM payload into sw1 sw2 data-hex. Values arrive either quoted or
# bare, and the data field is absent entirely when the card refused.
at_crsm_split() {  # <payload> -> sw1<TAB>sw2<TAB>hex
    local payload="${1:-}"
    local -a f=()
    mapfile -t f < <(at_csv "$payload")
    printf '%s\t%s\t%s' "${f[0]:-}" "${f[1]:-}" "$(at_norm_hex "${f[2]:-}")"
}

# +CSIM reports ONE quoted hex string whose last four characters are the status
# word; +CRSM reports them as two decimal fields. Two shapes, two splitters,
# because collapsing them loses exactly the distinction that matters — a CSIM
# read through at_crsm_split yields an SW1 of 0 and a data field four digits
# long, and the card looks empty rather than refused.
at_csim_split() {  # <payload> -> sw1<TAB>sw2<TAB>data-hex
    local h; h=$(at_norm_hex "${1//\"/}")
    local n=${#h}
    (( n >= 4 )) || { printf '\t\t'; return 1; }
    printf '%s\t%s\t%s' "$(( 16#${h:n-4:2} ))" "$(( 16#${h:n-2:2} ))" "${h:0:n-4}"
}

at_sim_decode() {  # <decoder> <hex> -> decoded value
    local dec="$1" h="$2"
    case "$dec" in
        iccid)
            local d; d=$(at_bcd_swap "$h")
            # TS 31.102: the first nibble pair is the card's leading digit; a
            # length octet is not part of EF_ICCID but some cards prepend one,
            # so a 20-digit result from 11 bytes is trimmed to 20.
            printf '%s' "${d:0:20}" ;;
        imsi)
            # Byte 1 is the length of the IMSI in octets; the digits follow it.
            local d; d=$(at_bcd_swap "${h:2}")
            printf '%s' "$d" ;;
        efad)
            local m; m=$(at_efad_mnc_len "$h" 2>/dev/null) || m=""
            printf '%s' "${m:-no-valid-mnc-length}" ;;
        spn)
            local cond="${h:0:2}"
            printf '%s\t%s' "$(at_gsm7_unpacked_alpha "${h:2}")" "$cond" ;;
        *)
            printf '%s' "$h" ;;
    esac
}

at_sim() {
    local port="${1:-}" mode="${2:-walk}" arg="${3:-}" arg2="${4:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }

    case "$mode" in
        csim)
            [[ -n "$arg" ]] || { printf 'ERROR\tcsim needs an APDU\n' >&2; return 2; }
            at_is_hex "$arg" || { printf 'ERROR\tAPDU is not an even-length hex string\n' >&2; return 2; }
            local apdu; apdu=$(at_norm_hex "$arg")
            local len=$(( ${#apdu} / 2 ))
            local resp; resp=$(at_cmd "$port" "AT+CSIM=$len,\"$apdu\"" 2)
            local payload; payload=$(at_field "$resp" '+CSIM' 2>/dev/null) || payload=""
            local out; out=$(at_csim_split "$payload")
            local sw1 sw2 data
            IFS=$'\t' read -r sw1 sw2 data <<< "$out"
            printf 'field\tvalue\n'
            printf 'apdu\t%s\n' "$apdu"
            printf 'sw1\t%s\nsw2\t%s\n' "$sw1" "$sw2"
            printf 'status\t%s\n' "$(at_sw_name "$sw1" "$sw2")"
            [[ -n "$data" ]] && printf 'data\t%s\n' "$data"
            return 0 ;;
        ef)
            [[ -n "$arg" ]] || { printf 'ERROR\tef needs a file id hex\n' >&2; return 2; }
            local fid; fid=$(at_norm_hex "$arg")
            [[ "$fid" =~ ^[0-9A-F]{4}$ ]] || { printf 'ERROR\tfile id must be four hex digits\n' >&2; return 2; }
            at_sim_one "$port" "$fid" "${arg2:-}"
            return 0 ;;
        walk|"") : ;;
        *) printf 'ERROR\tunknown sim mode: %s\n' "$mode" >&2; return 2 ;;
    esac

    local effile
    printf 'ef\tfile_id\tpath\tstatus\tdecoded\traw_hex\n'
    while IFS=$'\t' read -r effile fid path len dec; do
        [[ -n "$effile" ]] || continue
        at_sim_one "$port" "$fid" "$path" "$len" "$dec" "$effile"
    done < <(at_ef_table)
    return 0
}

at_sim_one() {  # <port> <fid> [path|len] [len] [dec] [name]
    local port="$1" fid="$2" path="${3:-}" len="${4:-}" dec="${5:-}" name="${6:-}"
    local -a row=()
    # Bare `--at-sim <port> ef <fid>`: look the file up so the path and length
    # are the table's rather than the operator's memory.
    if [[ -z "$path" ]]; then
        local ef_fid ef_path ef_len ef_dec ef_name
        while IFS=$'\t' read -r ef_name ef_fid ef_path ef_len ef_dec; do
            if [[ "$ef_fid" == "$fid" ]]; then
                path="$ef_path"; len="$ef_len"; dec="$ef_dec"; name="$ef_name"; break
            fi
        done < <(at_ef_table)
        # A file the table does not name is still readable: READ BINARY with a
        # generous length and no decoder is the honest default.
        [[ -n "$path" ]] || { path="3F007FFF"; len="32"; dec="hex"; name=""; }
    fi
    [[ -n "$name" ]] || name=$(printf '%s' "$fid" | tr 'A-F' 'a-f')

    local resp payload out sw1 sw2 data
    resp=$(at_crsm_read "$port" "$fid" "$path" "$len")
    payload=$(at_field "$resp" '+CRSM' 2>/dev/null) || payload=""
    if [[ -z "$payload" ]]; then
        local fin; fin=$(at_final "$resp")
        printf '%s\t%s\t%s\t%s\t\t\n' "$(at_tsv "$name")" "$fid" "$(at_tsv "$path")" \
            "$(at_tsv "no answer ($fin)")"
        return 0
    fi
    out=$(at_crsm_split "$payload")
    IFS=$'\t' read -r sw1 sw2 data <<< "$out"
    local status decoded="" note="" swh
    status=$(at_sw_name "$sw1" "$sw2")
    swh=$(printf '%02X%02X' "$(( ${sw1:-0} & 0xFF ))" "$(( ${sw2:-0} & 0xFF ))")
    # 9000 is a clean read; 62xx is a read the card completed with a warning,
    # and the data field is present in both.
    case "$swh" in
        90*|62*) [[ -n "$data" ]] && decoded=$(at_sim_decode "$dec" "$data") ;;
    esac
    # EF_SPN carries a display-condition octet in front of the alpha name; it
    # decides whether the handset shows the name at all, so it is reported
    # beside the name rather than silently dropped.
    if [[ "$dec" == "spn" && -n "$decoded" ]]; then
        local alpha cond
        IFS=$'\t' read -r alpha cond <<< "$decoded"
        decoded="$alpha"
        note="display_conditions=$cond"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(at_tsv "$name")" "$fid" "$(at_tsv "$path")" \
        "$(at_tsv "$status")" "$(at_tsv "${decoded:-}")" "$data"
    [[ -n "$note" ]] && printf '%s_detail\t%s\t%s\t%s\t%s\t\n' \
        "$(at_tsv "$name")" "$fid" "$(at_tsv "$path")" "$note" "$note"
}

# ── --at-walk ───────────────────────────────────────────────────────────
# Which of the documented commands this firmware actually accepts. Query forms
# only: nothing in this list changes radio state, writes a file or opens a
# socket, so a walk is safe to run against a device nobody told you about.
at_family_cmds() {  # <family>
    case "${1:-all}" in
        identity)
            cat <<'C'
ATI
AT+CGMI
AT+CGMM
AT+CGMR
AT+CGSN
AT+CIMI
AT+CCID
AT+CPIN?
AT+WS46?
C
            ;;
        network)
            cat <<'C'
AT+COPS?
AT+CREG?
AT+CEREG?
AT+CGREG?
AT+CSQ
AT+QNWINFO
AT+QENG="servingcell"
AT!GSTATUS?
AT^SYSINFO
C
            ;;
        sim)
            cat <<'C'
AT+CRSM=192,12258,0,0,15,"3F00"
AT+CSIM=14,"00A40004023F00"
C
            ;;
        control)
            cat <<'C'
AT+CFUN?
AT+COPS=?
AT+CGDCONT?
AT+CLCK="SC",2
C
            ;;
        nv)
            cat <<'C'
AT+EGMR=0,7
AT+QNVFR=0,1
C
            ;;
        stack)
            cat <<'C'
AT+QISTATE?
AT+QILOCIP
C
            ;;
        all|"")
            at_family_cmds identity
            at_family_cmds network
            at_family_cmds sim
            at_family_cmds control
            at_family_cmds nv
            at_family_cmds stack
            ;;
        *) printf 'ERROR\tunknown family: %s\n' "$1" >&2; return 2 ;;
    esac
}

at_walk() {
    local port="${1:-}" family="${2:-all}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }
    printf 'command\tverdict\tevidence\n'
    local cmd resp fin code evidence
    while IFS= read -r cmd; do
        [[ -n "$cmd" ]] || continue
        resp=$(at_cmd "$port" "$cmd" 1 2>/dev/null || true)
        fin=$(at_final "$resp")
        case "$fin" in
            ok)
                evidence=$(at_field "$resp" '+')
                [[ -n "$evidence" ]] || evidence="OK with no payload"
                printf '%s\taccepted\t%s\n' "$(at_tsv "$cmd")" "$(at_tsv "$evidence")" ;;
            error)
                printf '%s\trejected\tERROR\n' "$(at_tsv "$cmd")" ;;
            cme|cms)
                code=$(at_error_code "$resp")
                printf '%s\trejected\t%s %s (%s)\n' "$(at_tsv "$cmd")" \
                    "$fin" "$code" "$(at_cme_name "$code")" ;;
            *)
                printf '%s\tsilent\tno reply before the deadline\n' "$(at_tsv "$cmd")" ;;
        esac
    done < <(at_family_cmds "$family")
    return 0
}

# ── --at-ctrl ───────────────────────────────────────────────────────────
# Real state changes on a real device. Each one prints the command it sent, the
# final result and the device's own code, because "it returned OK" and "the
# radio is now off" are different reports and only one of them is true.
at_ctrl() {
    local port="${1:-}" action="${2:-}" a="${3:-}" b="${4:-}" c="${5:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }
    local cmd="" resp fin
    case "$action" in
        cops)
            [[ "$a" =~ ^[0-9]{5,6}$ ]] || { printf 'ERROR\tcops needs a 5 or 6 digit PLMN\n' >&2; return 2; }
            cmd="AT+COPS=1,2,\"$a\"" ;;
        cops-auto)
            cmd="AT+COPS=0" ;;
        apn)
            [[ -n "$a" ]] || { printf 'ERROR\tapn needs an APN\n' >&2; return 2; }
            cmd="AT+CGDCONT=${b:-1},\"IP\",\"$a\"" ;;
        lock)
            # lock <facility> <0|1> <password>; SC is the SIM lock, AO the
            # barring of all outgoing, OI / IR the barrings that matter.
            [[ -n "$a" && -n "$b" && -n "$c" ]] || {
                printf 'ERROR\tlock needs a facility, a mode and a password\n' >&2; return 2; }
            cmd="AT+CLCK=\"$a\",$b,\"$c\"" ;;
        unlock)
            [[ -n "$a" && -n "$c" ]] || {
                printf 'ERROR\tunlock needs a facility and a password\n' >&2; return 2; }
            cmd="AT+CLCK=\"$a\",0,\"$c\"" ;;
        cfun)
            [[ "$a" =~ ^[0-9]$ ]] || { printf 'ERROR\tcfun needs 0..4\n' >&2; return 2; }
            cmd="AT+CFUN=$a" ;;
        reset)
            cmd="AT+CFUN=1,1" ;;
        status)
            local q
            printf 'query\tvalue\tresult\n'
            for q in 'AT+CFUN?' 'AT+COPS?' 'AT+CGDCONT?' 'AT+CREG?' 'AT+CLCK="SC",2'; do
                resp=$(at_cmd "$port" "$q" 1 2>/dev/null || true)
                fin=$(at_final "$resp")
                printf '%s\t%s\t%s\n' "$(at_tsv "$q")" \
                    "$(at_tsv "$(at_lines "$resp" '' | grep -vE '^(OK|ERROR)$' | head -1)")" \
                    "$(at_tsv "$fin")"
            done
            return 0 ;;
        *) printf 'ERROR\tunknown action: %s\n' "$action" >&2; return 2 ;;
    esac

    resp=$(at_cmd "$port" "$cmd" 3)
    fin=$(at_final "$resp")
    printf 'field\tvalue\n'
    printf 'command\t%s\n' "$(at_tsv "$cmd")"
    printf 'result\t%s\n' "$fin"
    [[ "$fin" == cme || "$fin" == cms ]] && {
        local code; code=$(at_error_code "$resp")
        printf 'error_code\t%s\n' "$code"
        printf 'error_name\t%s\n' "$(at_cme_name "$code")"
    }
    local body; body=$(at_lines "$resp" "$cmd" | grep -vE '^(OK|ERROR)$' | head -3)
    [[ -n "$body" ]] && printf 'reply\t%s\n' "$(at_tsv "$body")"
    return 0
}

# ── --at-nv ─────────────────────────────────────────────────────────────
# The NV store is where calibration, provisioning and identity numbers live.
# Quectel spells it +QNVFR/+QNVFW over an item address the operator supplies;
# MediaTek spells the IMEI write +EGMR. Both dialects are here because a device
# speaks one of them and the operator should not have to guess which.
#
# No item-number table is shipped. No published table maps these addresses to
# semantics, and a hardcoded "item 5 is the IMEI" would be a guess dressed as a
# feature — the same decision 56_baseband_diag made and for the same reason.
at_nv() {
    local port="${1:-}" op="${2:-}" a="${3:-}" b="${4:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }
    local cmd="" resp fin
    case "$op" in
        read)
            [[ -n "$a" ]] || { printf 'ERROR\tread needs an NV item\n' >&2; return 2; }
            cmd="AT+QNVFR=$a${b:+,$b}" ;;
        write)
            [[ -n "$a" && -n "$b" ]] || { printf 'ERROR\twrite needs an item and a hex value\n' >&2; return 2; }
            at_is_hex "$b" || { printf 'ERROR\tvalue is not even-length hex\n' >&2; return 2; }
            cmd="AT+QNVFW=$a,${b^^}" ;;
        egmr)
            # +EGMR=<op>,<id>[,<data>]; op 0 reads, 1 writes.
            cmd="AT+EGMR=$a,$b${c:+,$c}" ;;
        imei)
            [[ -n "$a" ]] || { printf 'ERROR\tno IMEI given\n' >&2; return 2; }
            printf '%s' "$a" | grep -qE '^[0-9]{15}$' || { printf 'ERROR\tIMEI must be 15 digits\n' >&2; return 2; }
            at_luhn_ok "$a" || printf 'WARN\tIMEI check digit fails Luhn; sending anyway\n' >&2
            cmd="AT+EGMR=1,7,\"$a\"" ;;
        egmr-read)
            cmd="AT+EGMR=0,7" ;;
        *) printf 'ERROR\tunknown nv operation: %s\n' "$op" >&2; return 2 ;;
    esac

    resp=$(at_cmd "$port" "$cmd" 3)
    fin=$(at_final "$resp")
    printf 'field\tvalue\n'
    printf 'command\t%s\n' "$(at_tsv "$cmd")"
    printf 'result\t%s\n' "$fin"
    [[ "$fin" == cme || "$fin" == cms ]] && {
        local code; code=$(at_error_code "$resp")
        printf 'error_code\t%s\n' "$code"
        printf 'error_name\t%s\n' "$(at_cme_name "$code")"
    }
    local body; body=$(at_lines "$resp" "$cmd" | grep -vE '^(OK|ERROR)$' | head -5)
    [[ -n "$body" ]] && printf 'reply\t%s\n' "$(at_tsv "$body")"
    return 0
}

# ── --at-stack ──────────────────────────────────────────────────────────
# The modem's own TCP/IP stack. A socket opened here does not touch the host
# OS: the module makes the connection, holds it across a reboot, and keeps
# sending while the device it is bolted to is powered off. That property is the
# finding, so the arm both builds the command and sends it.
at_stack() {
    local port="${1:-}" op="${2:-}" a="${3:-}" b="${4:-}" c="${5:-}"
    [[ -n "$port" ]] || { printf 'ERROR\tno port given\n' >&2; return 2; }
    local cmd="" resp fin preview=0
    case "$op" in
        open)
            # open <tcp|udp> <host> <port> [connect-id]
            [[ -n "$a" && -n "$b" && -n "$c" ]] || {
                printf 'ERROR\topen needs <tcp|udp> <host> <port> [connect-id]\n' >&2; return 2; }
            local proto="${a^^}" cid="${4:-0}"
            case "$proto" in TCP|UDP) ;; *) printf 'ERROR\tprotocol must be TCP or UDP\n' >&2; return 2 ;; esac
            cmd="AT+QIOPEN=1,$cid,\"$proto\",\"$b\",$c,0,1" ;;
        send)
            [[ -n "$a" && -n "$b" ]] || { printf 'ERROR\tsend needs a connect-id and a payload\n' >&2; return 2; }
            if at_is_hex "$b"; then
                local n=$(( $(at_norm_hex "$b" | wc -c) / 2 ))
                cmd="AT+QISEND=$a,$n"
                preview=1
                resp=$(at_cmd "$port" "$cmd" 2)
                fin=$(at_final "$resp")
                printf 'field\tvalue\ncommand\t%s\nresult\t%s\n' "$cmd" "$fin"
                if [[ "$fin" == '>' || "$fin" == "ok" || "$fin" == "silent" ]]; then
                    resp=$(at_cmd "$port" "$(at_norm_hex "$b")" 2)
                    printf 'after_data\t%s\n' "$(at_final "$resp")"
                fi
                return 0
            fi
            local n=$(( ${#b} ))
            cmd="AT+QISEND=$a,$n" ;;
        close)
            [[ -n "$a" ]] || { printf 'ERROR\tclose needs a connect-id\n' >&2; return 2; }
            cmd="AT+QICLOSE=$a" ;;
        state)
            cmd="AT+QISTATE?" ;;
        http)
            # http <url> — the two-step QHTTP GET: length first, then the URL.
            [[ -n "$a" ]] || { printf 'ERROR\thttp needs a URL\n' >&2; return 2; }
            local n=$(( ${#a} ))
            printf 'field\tvalue\n'
            printf 'step\tset-url-length\n'
            printf 'command\t%s\n' "AT+QHTTPURL=$n,80"
            printf 'note\tafter the prompt, send the URL itself\n'
            printf 'then\tAT+QHTTPGET=80\n'
            printf 'url\t%s\n' "$(at_tsv "$a")"
            return 0 ;;
        raw)
            [[ -n "$a" ]] || { printf 'ERROR\traw needs an AT command\n' >&2; return 2; }
            cmd="$a${b:+ $b}${c:+ $c}" ;;
        *) printf 'ERROR\tunknown stack operation: %s\n' "$op" >&2; return 2 ;;
    esac

    resp=$(at_cmd "$port" "$cmd" 3)
    fin=$(at_final "$resp")
    printf 'field\tvalue\n'
    printf 'command\t%s\n' "$(at_tsv "$cmd")"
    printf 'result\t%s\n' "$fin"
    [[ "$fin" == cme || "$fin" == cms ]] && {
        local code; code=$(at_error_code "$resp")
        printf 'error_code\t%s\n' "$code"
        printf 'error_name\t%s\n' "$(at_cme_name "$code")"
    }
    local body; body=$(at_lines "$resp" "$cmd" | grep -vE '^(OK|ERROR)$' | head -5)
    [[ -n "$body" ]] && printf 'reply\t%s\n' "$(at_tsv "$body")"
    return 0
}

at_raw() {
    local port="${1:-}" cmd="${2:-}"
    [[ -n "$port" && -n "$cmd" ]] || { printf 'ERROR\traw needs a port and a command\n' >&2; return 2; }
    local resp fin
    resp=$(at_cmd "$port" "$cmd" 3)
    fin=$(at_final "$resp")
    printf 'field\tvalue\n'
    printf 'command\t%s\n' "$(at_tsv "$cmd")"
    printf 'result\t%s\n' "$fin"
    local body; body=$(at_lines "$resp" "$cmd" | grep -vE '^(OK|ERROR)$')
    printf 'reply\t%s\n' "$(at_tsv "$body")"
    return 0
}

# ── --at-plan ───────────────────────────────────────────────────────────
# What the parts that need a live device would do, in the order they would do
# it. A plan is a handoff with consequences named: which step changes state,
# which one cannot be undone, and which one the device may refuse by code.
at_plan() {
    local which="${1:-}"
    case "$which" in
        ""|all)
            printf 'step\toperation\tconsequence\n'
            printf '1\t--at-surface probe\tnone — reads sysfs and sends ATI\n'
            printf '2\t--at-session <port>\tnone — queries only\n'
            printf '3\t--at-walk <port>\tnone — query forms only by design\n'
            printf '4\t--at-sim <port>\tnone — READ BINARY, no write path\n'
            printf '5\t--at-eng <port>\tnone — vendor query pages\n'
            printf '6\t--at-ctrl <port> cops <plmn>\tforces manual network selection; survives until cops-auto\n'
            printf '7\t--at-ctrl <port> cfun 0\tradio off; the host loses network immediately\n'
            printf '8\t--at-ctrl <port> lock ...\treversible with unlock and the same password\n'
            printf '9\t--at-nv <port> write ...\tCALIBRATION AND IDENTITY LIVE HERE — a wrong item does not undo\n'
            printf '10\t--at-stack <port> open ...\tmodem-side socket; outlives the host OS\n' ;;
        surface|session|walk|sim|eng)
            printf 'step\toperation\tconsequence\n'
            printf '1\t--at-%s\tnone — read-only\n' "$which" ;;
        ctrl)
            printf 'step\toperation\tconsequence\n'
            printf '1\t--at-ctrl <port> status\tnone\n'
            printf '2\t--at-ctrl <port> cops <plmn>\tmanual selection; undo with cops-auto\n'
            printf '3\t--at-ctrl <port> apn <apn> [cid]\twrites the PDP context; undo by rewriting\n'
            printf '4\t--at-ctrl <port> cfun 0\tradio off; undo with cfun 1\n'
            printf '5\t--at-ctrl <port> reset\tCFUN=1,1; the modem re-attaches from scratch\n' ;;
        nv)
            printf 'step\toperation\tconsequence\n'
            printf '1\t--at-nv <port> read <item>\tnone — read path\n'
            printf '2\t--at-nv <port> egmr-read\tnone — reads the MediaTek IMEI slot\n'
            printf '3\t--at-nv <port> write <item> <hex>\tWRITES. No rollback: capture the old value with read first\n'
            printf '4\t--at-nv <port> imei <imei>\twrites the identity the network sees; irreversible without the original\n'
            printf 'note\tread the item before writing it, every time — the old value is the only backup there is\n' ;;
        stack)
            printf 'step\toperation\tconsequence\n'
            printf '1\t--at-stack <port> state\tnone\n'
            printf '2\t--at-stack <port> open tcp <host> <port>\topens a modem-side socket; visible to the network as this device\n'
            printf '3\t--at-stack <port> send <cid> <payload>\tsends from the modem, not the host\n'
            printf '4\t--at-stack <port> close <cid>\tcloses it; the socket is not persistent unless the module is\n' ;;
        *) printf 'ERROR\tunknown plan: %s\n' "$which" >&2; return 2 ;;
    esac
    return 0
}

# ── --status-tsv ────────────────────────────────────────────────────────
at_status() {
    local n=0 p
    printf 'key\tvalue\n'
    printf 'module\t64_modem_at\n'
    for p in /sys/class/tty/ttyUSB* /sys/class/tty/ttyACM* /dev/cdc-wdm* /sys/class/tty/wwan*; do
        [[ -e "$p" ]] && n=$(( n + 1 ))
    done
    printf 'modem_nodes\t%d\n' "$n"
    printf 'fake_tty\t%s\n' "$([[ -n "${MODEM_AT_FAKE:-}" ]] && printf yes || printf no)"
    if declare -F refdata_plmn >/dev/null 2>&1; then
        local st; st=$(refdata_plmn 208 01)
        printf 'plmn_register\t%s\n' "$(printf '%s' "$st" | cut -f1)"
    else
        printf 'plmn_register\tsilent\n'
    fi
    printf 'refdata_root\t%s\n' "${REFDATA_PUBLIC:-unset}"
    return 0
}

at_usage() {
    cat >&2 <<'EOF'
MODEM AT — the modem's own management port (TS 27.007 / 27.005 / 27.010)

Usage: 64_modem_at COMMAND

  --status-tsv                   module state as TSV

  Ports and identity
  --at-surface [probe]           every modem tty and QMI/MBIM node on this host,
                                 with vendor, product, family, USB interface
                                 and its role. 'probe' also sends ATI to each.
  --at-session <port>            the device page: make, model, firmware, IMEI
                                 with its TAC and Luhn result, IMSI split into
                                 MCC/MNC/MSIN, ICCID, SIM state, registered
                                 network, signal.
  --at-walk <port> [family]      which documented commands this firmware
                                 accepts — identity, network, sim, control,
                                 nv, stack, or all. Query forms only.

  Network
  --at-eng <port>                the serving cell, decoded into the same sixteen
                                 columns 02_cell_recon writes. Tries +QNWINFO,
                                 +QENG="servingcell", AT!GSTATUS? and
                                 AT^SYSINFO in that order and names which
                                 answered in the source column.
  --at-parse [file|-|text]       decode a saved AT transcript with the same
                                 parsers. No device, no radio.

  SIM
  --at-sim <port> [walk]         READ BINARY over every known USIM file: IMSI,
                                 ICCID, EF_AD (which supplies the real MNC
                                 length), SPN with its 7-bit alpha decoded.
  --at-sim <port> ef <fid>       one file by id, path and length from the table.
  --at-sim <port> csim <apdu>    an arbitrary APDU through AT+CSIM.

  Control
  --at-ctrl <port> <action> ...  cops <plmn> | cops-auto | apn <apn> [cid] |
                                 lock <fac> <0|1> <pw> | unlock <fac> <pw> |
                                 cfun <0-4> | reset | status

  NV
  --at-nv <port> <op> ...        read <item> [len] | write <item> <hex> |
                                 egmr <op> <id> [data] | egmr-read |
                                 imei <15 digits>

  Modem-side stack
  --at-stack <port> <op> ...     open <tcp|udp> <host> <port> [cid] |
                                 send <cid> <payload> | close <cid> |
                                 state | http <url> | raw <command>
  --at-raw <port> <command>      any AT command, sent verbatim.

  --at-plan [name]               what a live run would do and what each step
                                 costs — surface, session, walk, sim, eng,
                                 ctrl, nv, stack, or all
  --selftest                     every parser and the whole pipeline against a
                                 fake tty. No hardware, no root, no radio.
  --menu                         interactive menu

Every row this module writes is what the modem claims. `source` names which
vendor page said it, and a field that grammar does not carry is written as
not-advertised rather than as a zero.
EOF
}

# ── selftest ────────────────────────────────────────────────────────────
at_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=[%s] got=[%s]\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    # ── packed decimal ──────────────────────────────────────────────────
    chk bcd-swap          "$(at_bcd_swap 2143)" "1234"
    chk bcd-odd-pad       "$(at_bcd_swap 2143F5)" "12345"
    chk bcd-empty         "$(at_bcd_swap '')" ""

    # ── Luhn ────────────────────────────────────────────────────────────
    chk luhn-valid        "$(at_luhn_ok 353325060462136 && echo yes || echo no)" "yes"
    chk luhn-invalid      "$(at_luhn_ok 353325060462137 && echo yes || echo no)" "no"

    # ── IMSI split ──────────────────────────────────────────────────────
    local split mcc mnc msin conf
    split=$(at_imsi_split 001010123456789)
    IFS=$'\t' read -r mcc mnc msin conf <<< "$split"
    chk imsi-mcc          "$mcc" "001"
    chk imsi-mnc-2        "$mnc" "01"
    chk imsi-msin         "$msin" "0123456789"
    chk imsi-conf-2       "$conf" "default-2"
    split=$(at_imsi_split 001010123456789 3)
    IFS=$'\t' read -r mcc mnc msin conf <<< "$split"
    chk imsi-mnc-3        "$mnc" "010"
    chk imsi-conf-efad    "$conf" "EF_AD"
    split=$(at_imsi_split 310410123456789)
    IFS=$'\t' read -r mcc mnc msin conf <<< "$split"
    chk imsi-us-mnc3      "$mnc" "410"
    chk imsi-us-conf      "$conf" "table"
    chk imsi-bad          "$(at_imsi_split 12 2>/dev/null; echo rc=$?)" "rc=1"

    # ── EF_AD MNC length (TS 31.102 §4.2.18) ────────────────────────────
    # byte4 = 0x02 -> two digits; 0x03 -> three; 0x05 is reserved.
    chk efad-mnc-2        "$(at_efad_mnc_len 00000002)" "2"
    chk efad-mnc-3        "$(at_efad_mnc_len 00000003)" "3"
    chk efad-reserved     "$(at_efad_mnc_len 00000005 2>/dev/null; echo rc=$?)" "rc=1"

    # ── GSM 7-bit default alphabet (TS 23.038 §6.2.1) ───────────────────
    # The standard worked example. 0xC8 in the first octet is septet 0x48,
    # which is 'H'; 0xE8 differs only in that bit and yields 'h'. Asserting
    # both proves the high bit of octet zero is read and not discarded.
    chk gsm7-packed-upper "$(at_gsm7_unpack C8329BFD06)" "Hello"
    chk gsm7-packed-lower "$(at_gsm7_unpack E8329BFD06)" "hello"
    chk gsm7-unpacked     "$(at_gsm7_unpacked_alpha 68656C6C6FFFFFFFFF)" "hello"
    # 0x24 is ¤ and 0x40 is ¡ — the two that a plain ASCII mapper gets wrong.
    chk gsm7-currency     "$(at_gsm7_unpacked_alpha 24)" "¤"
    chk gsm7-inverted     "$(at_gsm7_unpacked_alpha 40)" "¡"

    # ── frequency arithmetic ────────────────────────────────────────────
    chk earfcn-band3      "$(at_lte_earfcn_mhz 1650)" "1850.0"
    chk earfcn-band1      "$(at_lte_earfcn_mhz 100)" "2120.0"
    chk earfcn-unknown    "$(at_lte_earfcn_mhz 999999 2>/dev/null; echo rc=$?)" "rc=1"
    # 632000 is 32000 steps of 15 kHz above 3000 MHz -> 3480.000.
    chk nr-arfcn-mid      "$(at_nr_arfcn_mhz 632000)" "3480.000"
    # 2016667 is the 24250.08 MHz pivot; 2080000 is 63333 steps of 60 kHz on.
    chk nr-arfcn-pivot    "$(at_nr_arfcn_mhz 2016667)" "24250.080"
    chk nr-arfcn-high     "$(at_nr_arfcn_mhz 2080000)" "28050.060"

    # ── signal, status words, error codes ───────────────────────────────
    chk csq-20            "$(at_csq_dbm 20)" "-73"
    chk csq-0             "$(at_csq_dbm 0)" "-113"
    chk csq-unknown       "$(at_csq_dbm 99)" "not-advertised"
    # +CRSM reports "144,0" for 0x90 0x00, so the arguments are decimal.
    chk sw-ok             "$(at_sw_name 144 0)" "success"
    chk sw-missing        "$(at_sw_name 106 130)" "file or application not found"
    chk sw-security       "$(at_sw_name 105 130)" "security status not satisfied"
    chk sw-pin-attempts   "$(at_sw_name 99 194)" "verification failed, 2 attempt(s) left"
    chk cme-58            "$(at_cme_name 58)" "unsupported command"
    chk cme-111           "$(at_cme_name 111)" "PLMN not allowed"
    chk cme-unknown       "$(at_cme_name 999)" "code 999"
    chk act-lte           "$(at_act_name 7)" "E-UTRAN (LTE)"
    chk act-nr            "$(at_act_gen 9)" "5G"

    # ── final-result classification ─────────────────────────────────────
    chk final-ok          "$(at_final $'\r\nOK\r\n')" "ok"
    chk final-error       "$(at_final $'\r\nERROR\r\n')" "error"
    chk final-cme         "$(at_final $'\r\n+CME ERROR: 58\r\n')" "cme"
    chk final-silent      "$(at_final '')" "silent"
    chk final-error-code  "$(at_error_code $'\r\n+CME ERROR: 58\r\n')" "58"

    # ── field and CSV extraction ────────────────────────────────────────
    chk field-quoted      "$(at_field $'+QNWINFO: "FDD LTE","46000","LTE BAND 3",1650\r\n' '+QNWINFO')" '"FDD LTE","46000","LTE BAND 3",1650'
    chk csv-count         "$(at_csv '1,"two",3' | wc -l | tr -d ' ')" "3"
    chk csv-unquoted      "$(at_csv '1,"two",3' | sed -n 2p)" "two"
    chk field-missing     "$(at_field 'nothing here' '+CGSN' 2>/dev/null; echo rc=$?)" "rc=1"

    # ── vendor engineering decoders ─────────────────────────────────────
    local out qn
    qn=$(at_eng_qnwin $'+QNWINFO: "FDD LTE","20801","LTE BAND 3",1650\r\n')
    chk qnwin-rat         "$(printf '%s' "$qn" | cut -f1)" "FDD LTE"
    chk qnwin-mcc         "$(printf '%s' "$qn" | cut -f2)" "208"
    chk qnwin-mnc         "$(printf '%s' "$qn" | cut -f3)" "01"
    chk qnwin-band        "$(printf '%s' "$qn" | cut -f4)" "3"
    chk qnwin-chan        "$(printf '%s' "$qn" | cut -f5)" "1650"

    # +QENG="servingcell",... LTE: state,LTE,is_tdd,mcc,mnc,cellid,pcid,
    # earfcn,band,ulbw,dlbw,tac,rsrp,rsrq,rssi,sinr
    local qeng_payload='"servingcell",1,"LTE",0,208,01,0A1B2C3,45,1650,3,20,20,1A2B,-95,-11,-65,12'
    out=$(at_eng_quectel_serving "$qeng_payload")
    chk qeng-rat          "$(printf '%s' "$out" | cut -f1)" "LTE"
    chk qeng-gen          "$(printf '%s' "$out" | cut -f2)" "4G"
    chk qeng-arfcn        "$(printf '%s' "$out" | cut -f3)" "1650"
    chk qeng-freq         "$(printf '%s' "$out" | cut -f4)" "1850.0"
    chk qeng-plmn         "$(printf '%s' "$out" | cut -f5)" "208-01"
    chk qeng-cellid       "$(printf '%s' "$out" | cut -f10)" "0A1B2C3"
    chk qeng-tac          "$(printf '%s' "$out" | cut -f11)" "1A2B"
    chk qeng-band         "$(printf '%s' "$out" | cut -f12)" "3"
    chk qeng-rsrp         "$(printf '%s' "$out" | cut -f13)" "-95"
    chk qeng-cipher       "$(printf '%s' "$out" | cut -f14)" "not-advertised"
    chk qeng-source       "$(printf '%s' "$out" | cut -f15)" "quectel-qeng"
    chk qeng-operator     "$(printf '%s' "$out" | cut -f8 | grep -c 'unknown')" "0"

    # The WCDMA page's field order is not pinned by any published table, so
    # the decoder must refuse it rather than guess which column is the cell id.
    # Refusing is what lets --at-eng fall through to +COPS/+CSQ, which reports
    # the operator and leaves the cell fields unobserved.
    chk qeng-wcdma-refused "$(at_eng_quectel_serving '"servingcell",1,"WCDMA",208,01,10688,0A1B2C3,45,-95' >/dev/null 2>&1; echo rc=$?)" "rc=1"
    chk qeng-gsm-refused   "$(at_eng_quectel_serving '"servingcell",1,"GSM",208,01,0A1B,45,-95' >/dev/null 2>&1; echo rc=$?)" "rc=1"
    # NR5G-SA shares the LTE prefix convention and IS decoded.
    out=$(at_eng_quectel_serving '"servingcell","NR5G-SA","FDD",208,01,0A1B2C3,45,1A2B,632000,78,100,-88,-10,15,1,60')
    chk qeng-nr-rat       "$(printf '%s' "$out" | cut -f1)" "5G NR"
    chk qeng-nr-arfcn     "$(printf '%s' "$out" | cut -f3)" "632000"
    chk qeng-nr-freq      "$(printf '%s' "$out" | cut -f4)" "3480.000"

    out=$(at_eng_sierra $'!GSTATUS: \r\nSystem mode:   LTE        	PS state:    Attached\r\nLTE band:      B3     		LTE bw:      20 MHz\r\nLTE Rx chan:   1650		LTE Tx chan: 19650\r\nPCC RxM RSRP: -87		PCC RxM RSRQ: -11\r\n')
    chk gstat-rat         "$(printf '%s' "$out" | cut -f1)" "LTE"
    chk gstat-arfcn       "$(printf '%s' "$out" | cut -f3)" "1650"
    chk gstat-band        "$(printf '%s' "$out" | cut -f12)" "B3"
    chk gstat-rsrp        "$(printf '%s' "$out" | cut -f13)" "-87"

    out=$(at_eng_huawei $'^SYSINFO: 2,1,0,10,1,0\r\n')
    chk sysinfo-rat       "$(printf '%s' "$out" | cut -f1)" "LTE"
    chk sysinfo-gen       "$(printf '%s' "$out" | cut -f2)" "4G"
    chk sysinfo-unobserved "$(printf '%s' "$out" | cut -f12)" "not-advertised"

    # ── the fake tty, end to end ────────────────────────────────────────
    # MODEM_AT_FAKE is built from the same key function the runtime looks up
    # with, so a fixture can never drift from the command it answers.
    local fake; fake=$(mktemp -d)
    local saved_fake="${MODEM_AT_FAKE:-}"
    export MODEM_AT_FAKE="$fake"
    mk() { printf '%s' "$2" > "$fake/$(at_fake_key "$1")"; }
    mk 'ATI'            $'\r\nQuectel\r\nEC25\r\nRevision: EC25EFAR06A11M4G\r\n\r\nOK\r\n'
    mk 'AT+CGMI'        $'\r\nQuectel\r\nOK\r\n'
    mk 'AT+CGMM'        $'\r\nEC25\r\nOK\r\n'
    mk 'AT+CGMR'        $'\r\nEC25EFAR06A11M4G\r\nOK\r\n'
    mk 'AT+CGSN'        $'\r\n860000000000001\r\nOK\r\n'
    mk 'AT+CIMI'        $'\r\n001010123456789\r\nOK\r\n'
    mk 'AT+CCID'        $'\r\n89860012345678901234\r\nOK\r\n'
    mk 'AT+CPIN?'       $'\r\n+CPIN: READY\r\nOK\r\n'
    mk 'AT+WS46?'       $'\r\n+WS46: (12,22,25)\r\nOK\r\n'
    mk 'AT+COPS?'       $'\r\n+COPS: 0,0,"Test Operator",7\r\nOK\r\n'
    mk 'AT+CREG?'       $'\r\n+CREG: 0,1\r\nOK\r\n'
    mk 'AT+CSQ'         $'\r\n+CSQ: 20,99\r\nOK\r\n'
    mk 'AT+QNWINFO'     $'\r\n+QNWINFO: "FDD LTE","00101","LTE BAND 3",1650\r\nOK\r\n'
    mk 'AT+QENG="servingcell"' $'\r\n+QENG: "servingcell",1,"LTE",0,001,01,0A1B2C3,45,1650,3,20,20,1A2B,-95,-11,-65,12\r\nOK\r\n'
    mk 'AT+CGDCONT?'    $'\r\n+CGDCONT: 1,"IP","internet","",0,0\r\nOK\r\n'
    mk 'AT+CFUN?'       $'\r\n+CFUN: 1\r\nOK\r\n'
    mk 'AT+CLCK="SC",2' $'\r\n+CLCK: 0\r\nOK\r\n'
    mk 'AT+COPS=1,2,"20801"' $'\r\nOK\r\n'
    mk 'AT+CFUN=0'      $'\r\n+CME ERROR: 3\r\n'
    mk 'AT+EGMR=0,7'    $'\r\n+EGMR: "353325060462136"\r\nOK\r\n'
    # CRSM: EF_IMSI (6F07 = 28423) under the USIM ADF, EF_ICCID (2FE2 =
    # 12258) under the MF, EF_AD (6FAD = 28589) with MNC length 3, EF_SPN.
    mk 'AT+CRSM=176,28423,0,0,9,"3F007FFF"' $'\r\n+CRSM: 144,0,"0800010121436587F9"\r\nOK\r\n'
    mk 'AT+CRSM=176,12258,0,0,10,"3F00"'    $'\r\n+CRSM: 144,0,"98680021436587092143"\r\nOK\r\n'
    mk 'AT+CRSM=176,28589,0,0,4,"3F007FFF"' $'\r\n+CRSM: 144,0,"00000003"\r\nOK\r\n'
    mk 'AT+CRSM=176,28486,0,0,17,"3F007FFF"' $'\r\n+CRSM: 105,130,""\r\nOK\r\n'

    out=$(at_session /dev/fake 2>/dev/null)
    chk session-manufacturer "$(fld "$out" manufacturer)" "Quectel"
    chk session-model      "$(fld "$out" model)" "EC25"
    chk session-firmware   "$(fld "$out" firmware)" "EC25EFAR06A11M4G"
    chk session-imei       "$(fld "$out" imei)" "860000000000001"
    chk session-tac        "$(fld "$out" imei_tac)" "86000000"
    chk session-imsi       "$(fld "$out" imsi)" "001010123456789"
    chk session-mcc        "$(fld "$out" imsi_mcc)" "001"
    chk session-mnc        "$(fld "$out" imsi_mnc)" "01"
    chk session-iccid      "$(fld "$out" iccid)" "89860012345678901234"
    chk session-sim        "$(fld "$out" sim_state)" "READY"
    chk session-operator   "$(fld "$out" registered_operator)" "Test Operator"
    chk session-act        "$(fld "$out" registered_gen)" "4G"
    chk session-rssi       "$(fld "$out" rssi_dbm)" "-73"

    out=$(at_eng /dev/fake 2>/dev/null)
    chk eng-header         "$(printf '%s\n' "$out" | head -1 | cut -f1)" "rat"
    chk eng-qnwin-row      "$(printf '%s\n' "$out" | sed -n 2p | cut -f15)" "quectel-qnwin"
    chk eng-qeng-row       "$(printf '%s\n' "$out" | sed -n 3p | cut -f15)" "quectel-qeng"
    chk eng-qeng-cellid    "$(printf '%s\n' "$out" | sed -n 3p | cut -f10)" "0A1B2C3"

    out=$(at_sim /dev/fake 2>/dev/null)
    chk sim-imsi-row       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EF_IMSI"{print $5}')" "001010123456789"
    chk sim-iccid-row      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EF_ICCID"{print $5}')" "89860012345678901234"
    chk sim-efad-row       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EF_AD"{print $5}')" "3"
    chk sim-spn-refused    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EF_SPN"{print $4}')" "security status not satisfied"

    # A single file by id, and the table supplying its path.
    out=$(at_sim /dev/fake ef 6f07 2>/dev/null)
    chk sim-single-decoded "$(printf '%s\n' "$out" | cut -f5)" "001010123456789"
    chk sim-single-path    "$(printf '%s\n' "$out" | cut -f3)" "3F007FFF"

    out=$(at_walk /dev/fake identity 2>/dev/null)
    chk walk-accepted      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AT+CGSN"{print $2}')" "accepted"
    chk walk-cme-name      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AT+CGMI"{print $2}')" "accepted"

    out=$(at_ctrl /dev/fake cops 20801 2>/dev/null)
    chk ctrl-cops-result   "$(fld "$out" result)" "ok"
    chk ctrl-cops-built    "$(grep -c 'AT+COPS=1,2,"20801"' "$fake/.sent")" "1"
    out=$(at_ctrl /dev/fake cfun 0 2>/dev/null)
    chk ctrl-cfun-refused  "$(fld "$out" result)" "cme"
    chk ctrl-cfun-code     "$(fld "$out" error_code)" "3"
    chk ctrl-cfun-name     "$(fld "$out" error_name)" "operation not allowed"

    out=$(at_nv /dev/fake egmr-read 2>/dev/null)
    chk nv-egmr-result     "$(fld "$out" result)" "ok"
    chk nv-egmr-value      "$(fld "$out" reply | tr -d '"')" "+EGMR: 353325060462136"

    out=$(at_raw /dev/fake 'AT+CGSN' 2>/dev/null)
    chk raw-result         "$(fld "$out" result)" "ok"
    chk raw-reply          "$(fld "$out" reply)" "860000000000001"

    # The status words are read from what the card said, not from a success
    # path: 6982 in a walk must not be reported as a read.
    chk sw-warning-6982    "$(at_sw_name 105 130)" "security status not satisfied"

    # ── --at-parse, offline ─────────────────────────────────────────────
    out=$(at_parse_stream $'AT+CGSN\r\n353325060462136\r\nOK\r\n+CSQ: 20,99\r\nOK\r\n')
    chk parse-imei         "$(fld "$out" +CGSN)" "353325060462136"
    chk parse-csq          "$(fld "$out" +CSQ)" "20,99"

    # ── plan and usage ──────────────────────────────────────────────────
    out=$(at_plan nv 2>/dev/null)
    chk plan-nv-warns      "$(printf '%s' "$out" | grep -c 'irreversible')" "1"
    out=$(at_plan all 2>/dev/null)
    chk plan-all-steps     "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')" "10"

    # ── surface on a host with no modem must still print a header ───────
    out=$(at_surface 2>/dev/null)
    chk surface-header     "$(printf '%s\n' "$out" | head -1 | cut -f1)" "port"

    # ── cleanup ─────────────────────────────────────────────────────────
    if [[ -n "$saved_fake" ]]; then export MODEM_AT_FAKE="$saved_fake"; else unset MODEM_AT_FAKE; fi
    rm -rf "$fake"

    printf 'RESULT\t%s\n' "$([ "$bad" -eq 0 ] && echo PASS || echo "FAIL bad=$bad")"
    (( bad == 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
at_menu() {
    local c port
    printf '\n  Modem AT surface (TS 27.007)\n'
    printf '  port: '; read -r port
    [[ -n "$port" ]] || port="/dev/ttyUSB2"
    while true; do
        printf '\n  port: %s\n' "$port"
        printf '  1) find the ports        6) SIM file walk\n'
        printf '  2) device identity       7) radio control\n'
        printf '  3) walk what it accepts  8) NV items\n'
        printf '  4) serving cell          9) modem-side stack\n'
        printf '  5) decode a transcript   0) back\n'
        read -rp '  choice: ' c
        case "$c" in
            1) read -rp '  probe the ports? [y/N] ' h; [[ "$h" == y* ]] && at_surface probe || at_surface ;;
            2) at_session "$port" ;;
            3) read -rp '  family [all]: ' h; at_walk "$port" "${h:-all}" ;;
            4) at_eng "$port" ;;
            5) read -rp '  transcript file: ' h; at_parse_stream "$h" ;;
            6) at_sim "$port" ;;
            7) read -rp '  action (status/cops/apn/lock/cfun/reset): ' h
               read -rp '  args: ' a; at_ctrl "$port" "$h" $a ;;
            8) read -rp '  op (read/write/egmr-read/imei): ' h
               read -rp '  args: ' a; at_nv "$port" "$h" $a ;;
            9) read -rp '  op (state/open/send/close/raw): ' h
               read -rp '  args: ' a; at_stack "$port" "$h" $a ;;
            0) return ;;
            *) printf '  invalid\n' ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
at_cli_main() {
    local cmd="${1:-}"
    (( $# > 0 )) && shift
    case "$cmd" in
        --status-tsv)  at_status ;;
        --at-surface)  at_surface "${1:-}" ;;
        --at-session)  at_session "${1:-}" ;;
        --at-walk)     at_walk "${1:-}" "${2:-all}" ;;
        --at-eng)      at_eng "${1:-}" ;;
        --at-parse)    at_parse_stream "${1:-}" ;;
        --at-sim)      at_sim "${1:-}" "${2:-walk}" "${3:-}" "${4:-}" ;;
        --at-ctrl)     at_ctrl "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --at-nv)       at_nv "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --at-stack)    at_stack "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --at-raw)      at_raw "${1:-}" "$*" && true ;;
        --at-plan)     at_plan "${1:-}" ;;
        --selftest)    at_selftest ;;
        --menu)        at_menu ;;
        -h|--help|"")  at_usage; [[ -n "$cmd" ]] && return 0 || return 2 ;;
        *)             at_usage; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    at_cli_main "$@"
fi
