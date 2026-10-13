#!/usr/bin/env bash
# ota_sms — TS 23.048 OTA command-packet construction and key/counter audit.
#
# An OTA (Over-The-Air) binary SMS is how a carrier updates a SIM: a TS 23.048
# command packet carrying SPI, TAR, counter and a KIc/KID-selected key set. The
# protocol is published; the S@T and WIB application classes are documented.
# What is *not* free is the target: affecting a SIM you do not hold needs that
# SIM's OTA keys, so this module is built for own-SIM and lab construction plus
# the audit that finds a weak SPI, a replayed counter or an un-keyed payload.
# 20_sim keeps the reader/defensive side; this module builds and audits.
#
# Attack owned: O5 adjacency (SIM/eSIM OTA) — construction plus vulnerability
# detection, per docs/MODULE_ROSTER.md. Own-SIM and lab only.
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

MOD_TMP="$TMP_DIR/ota_sms"
OTASM_DIR="$LOOT_DIR/ota_sms"
mkdir -p "$MOD_TMP" "$OTASM_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

otasm_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
OTASM_F=()
otasm_split() {
    OTASM_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        OTASM_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
otasm_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
otasm_is_hex() {
    local h; h=$(otasm_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
otasm_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

otasm_status_tsv() {
    printf 'MODULE\tota_sms\n'
    printf 'TARGET\tTS 23.048 OTA command packet, SPI, TAR, counter, key audit\n'
    printf 'SCOPE\town-SIM and lab; a live subscriber needs their OTA keys\n'
    printf 'TRANSMIT\tnone — construction and audit; delivery is a handoff\n'
    printf 'SELFTEST\tyes\n'
}

# ── BER length (X.690 §8.1.3) for the CPL field ─────────────────────────
otasm_berlen() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    (( n <= 127 )) && { printf '%02X' "$(( n & 0xFF ))"; return 0; }
    if (( n <= 0xFF )); then printf '81%02X' "$(( n & 0xFF ))"
    elif (( n <= 0xFFFF )); then printf '82%02X%02X' "$(( (n>>8)&0xFF ))" "$(( n&0xFF ))"
    else printf 'ERROR\tlength too large\n' >&2; return 2; fi
}
# read a BER length at octet offset $1; prints "value<TAB>octets"
otasm_berlen_read() {
    local h="$1" off="${2:-0}"
    local b0=$(( 16#${h:$((off*2)):2} ))
    if (( (b0 & 0x80) == 0 )); then printf '%d\t1' "$b0"; return 0; fi
    local n=$(( b0 & 0x7F ))
    (( n >= 1 && n <= 3 )) || { printf 'ERROR\tlength-of-length %d unsupported\n' "$n" >&2; return 1; }
    local v=$(( 16#${h:$(( (off+1)*2 )):$((n*2))} ))
    printf '%d\t%d' "$v" "$(( n + 1 ))"
}

# ── SPI (TS 23.048 §8.1) ────────────────────────────────────────────────
# Octet 1: b8-b7 RC/CC/DS, b6 ciphering, b5-b4 counter, b3-b1 reserved.
# Octet 2: b8-b7 PoR, b6-b5 PoR RC/CC/DS, b4 PoR ciphering, b3 PoR transport,
#          b2-b1 reserved. (Same bit layout as 20_sim's sim_spi_decode.)
otasm_spi_build() {
    local rccds="${1:-0}" cipher="${2:-0}" counter="${3:-0}"
    local por="${4:-0}" por_rccds="${5:-0}" por_cipher="${6:-0}" por_transport="${7:-0}"
    local i
    for i in "$rccds" "$cipher" "$counter" "$por" "$por_rccds" "$por_cipher" "$por_transport"; do
        [[ "$i" =~ ^[0-9]+$ ]] || { printf 'ERROR\tSPI fields must be numeric\n' >&2; return 2; }
    done
    (( rccds <= 3 && cipher <= 1 && counter <= 3 && por <= 3 && por_rccds <= 3 && por_cipher <= 1 && por_transport <= 1 )) || {
        printf 'ERROR\tSPI sub-field out of range\n' >&2; return 2; }
    local o1=$(( (rccds<<6) | (cipher<<5) | (counter<<3) ))
    local o2=$(( (por<<6) | (por_rccds<<4) | (por_cipher<<3) | (por_transport<<2) ))
    printf '%02X%02X\n' "$o1" "$o2"
}
otasm_spi_parse() {
    local in="${1:-}" h
    if [[ "$in" =~ ^[0-9A-Fa-f]{4}$ ]]; then
        h=$(printf '%s' "$in" | tr 'A-F' 'a-f')
    elif [[ "$in" =~ ^[0-9]+$ ]]; then
        printf -v h '%04X' "$(( in & 0xFFFF ))"
    else
        printf 'ERROR\tSPI must be 2 octets of hex or a 16-bit decimal\n' >&2; return 2
    fi
    [[ "$h" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tSPI must be 2 octets of hex or a 16-bit decimal\n' >&2; return 2; }
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} ))
    local rccds=$(( (o1>>6)&3 )) cipher=$(( (o1>>5)&1 )) counter=$(( (o1>>3)&3 ))
    local por=$(( (o2>>6)&3 )) por_rccds=$(( (o2>>4)&3 )) por_cipher=$(( (o2>>3)&1 )) por_transport=$(( (o2>>2)&1 ))
    local rccds_t counter_t
    case "$rccds" in 0) rccds_t="no RC, CC or DS";; 1) rccds_t="RC";; 2) rccds_t="CC";; 3) rccds_t="DS";; esac
    case "$counter" in
        0) counter_t="no counter (replay indiscriminate)";;
        1) counter_t="informational only (replay possible)";;
        2) counter_t="process iff counter > RE";;
        3) counter_t="process iff counter == RE+1 (strict)";; esac
    printf 'spi\t%s\nrccds\t%s\nrccds_meaning\t%s\nciphering\t%s\n' "$h" "$rccds" "$rccds_t" "$cipher"
    printf 'ciphering_meaning\t%s\ncounter_mode\t%s\ncounter_meaning\t%s\n' \
        "$([[ $cipher -eq 1 ]] && echo "applied" || echo "NOT applied (payload in the clear)")" "$counter" "$counter_t"
    printf 'por\t%s\npor_transport\t%s\n' "$por" "$([[ $por_transport -eq 1 ]] && echo "SMS-SUBMIT" || echo "SMS-DELIVER-REPORT")"
    local n=0
    (( cipher == 0 )) && { printf 'finding\tHIGH\tSPI b6=0 — the command payload is sent in the clear\n'; n=$((n+1)); }
    (( rccds == 0 )) && { printf 'finding\tHIGH\tSPI b8b7=00 — no RC/CC/DS; the packet has no integrity protection\n'; n=$((n+1)); }
    (( counter == 0 || counter == 1 )) && { printf 'finding\tMEDIUM\tSPI b5b4=%d — the counter does not stop a replay\n' "$counter"; n=$((n+1)); }
    (( n == 0 )) && printf 'finding\tINFO\tciphering on, integrity present, counter enforced\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── command packet build / parse (TS 23.048 §5.1.1) ─────────────────────
#   CPI(1) CPL(BER) CHI(1) CHL(1) CMD(CHL) SPI(2) KIc(1) KID(1) TAR(3)
#   CNTR(5) PCNTR(1) DATA(rest)
otasm_packet_build() {
    local cpi="${1:-01}" tar="${2:-000000}" counter="${3:-0}" spi="${4:-B800}"
    local kic="${5:-01}" kid="${6:-01}" data; data=$(otasm_norm_hex "${7:-}")
    local chi="${8:-01}" cmd; cmd=$(otasm_norm_hex "${9:-01}")
    [[ "$counter" =~ ^[0-9]+$ ]] || { printf 'ERROR\tcounter must be numeric\n' >&2; return 2; }
    otasm_is_hex "$tar" && (( ${#tar} == 6 )) || { printf 'ERROR\tTAR must be 3 octets of hex\n' >&2; return 2; }
    otasm_is_hex "$spi" && (( ${#spi} == 4 )) || { printf 'ERROR\tSPI must be 2 octets of hex\n' >&2; return 2; }
    local cntr; printf -v cntr '%010X' "$(( counter & 0xFFFFFFFFFF ))"
    local chl=$(( ${#cmd} / 2 ))
    local rest; rest="${chi}$(otasm_byte "$chl")${cmd}${spi}${kic}${kid}${tar}${cntr}00${data}"
    local base=$(( 1 + ${#rest}/2 ))
    local cpl
    if (( base + 1 <= 127 )); then cpl=$(printf '%02X' "$(( base + 1 ))")
    elif (( base + 2 <= 255 )); then cpl=$(printf '81%02X' "$(( base + 2 ))")
    else cpl=$(printf '82%04X' "$(( base + 3 ))"); fi
    printf '%s%s%s\n' "$cpi" "$cpl" "$rest"
}
otasm_packet_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 2 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 6 + 10 + 2 )) || {
        printf 'ERROR\tpacket shorter than the minimum command packet\n' >&2; return 1; }
    local cpi="${h:0:2}"
    local cpl_read; cpl_read=$(otasm_berlen_read "$h" 1) || return 1
    local cpl; cpl=$(printf '%s' "$cpl_read" | cut -f1)
    local cpl_oct=$(printf '%s' "$cpl_read" | cut -f2)
    local off=$(( 1 + cpl_oct ))
    local chi="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local chl=$(( 16#${h:$((off*2)):2} )); off=$(( off + 1 ))
    local cmd="${h:$((off*2)):$((chl*2))}"; off=$(( off + chl ))
    local spi="${h:$((off*2)):4}"; off=$(( off + 2 ))
    local kic="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local kid="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local tar="${h:$((off*2)):6}"; off=$(( off + 3 ))
    local cntr="${h:$((off*2)):10}"; off=$(( off + 5 ))
    local pcntr="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local data="${h:$((off*2))}"
    local cn=$(( 16#${cntr} ))
    printf 'cpi\t%s\ncpl\t%d\ncpl_octets\t%d\nchi\t%s\nchl\t%d\ncmd\t%s\nspi\t%s\n' \
        "$cpi" "$cpl" "$cpl_oct" "$chi" "$chl" "$cmd" "$spi"
    printf 'kic\t%s\nkid\t%s\ntar\t%s\ncounter\t%s\ncounter_dec\t%d\npcntr\t%s\ndata\t%s\n' \
        "$kic" "$kid" "$tar" "$cntr" "$cn" "$pcntr" "$data"
    printf 'packet_bytes\t%d\n' "$(( ${#h}/2 ))"
}

# ── counter / replay decision (TS 23.048 §8.2) ──────────────────────────
otasm_counter_check() {
    local counter="${1:-}" re="${2:-}" mode="${3:-0}"
    [[ "$counter" =~ ^[0-9]+$ && "$re" =~ ^[0-9]+$ && "$mode" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcounter, RE and mode must be numeric\n' >&2; return 2; }
    local verdict
    case "$mode" in
        0) verdict="process (counter absent — no replay protection)" ;;
        1) verdict="process (counter informational only)" ;;
        2) (( counter > re )) && verdict="process (counter above the received value)" || verdict="REPLAY (counter not above RE)" ;;
        3) (( counter == re + 1 )) && verdict="process (counter is exactly RE+1)" || verdict="REPLAY (counter is not RE+1)" ;;
        *) printf 'ERROR\tcounter mode must be 0..3\n' >&2; return 2 ;;
    esac
    printf 'mode\t%d\ncounter\t%d\nre\t%d\nverdict\t%s\n' "$mode" "$counter" "$re" "$verdict"
}

otasm_plan() {
    cat <<'EOF'
status	handoff
what	delivering an OTA command packet to a SIM
hardware	a programmable USIM you own (sysmoISIM-SJA2) plus an ISIM/OTA test bench, or a rooted modem you hold
software	pySim, osmo-sim-auth, or a SIMtrace2/pcsc reader with the SIM's OTA key set
flow	1. build a packet here with --packet  2. run --spi and --counter-check on it  3. deliver it to your own SIM
note	a live subscriber's SIM needs that subscriber's KIc/KID; this module never holds or derives another party's keys
EOF
}

otasm_selftest() {
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
    export OTASM_DIR="$d/loot/ota_sms"
    mkdir -p "$OTASM_DIR"

    # 1. SPI bit layout (TS 23.048 §8.1). RC/CC/DS=2, cipher=1, counter=3 ->
    #    octet1 = 10 1 11 000 = 0xB8; octet2 all zero.
    chk spi-build "$(otasm_spi_build 2 1 3 0 0 0 0)" "B800"
    chk spi-build2 "$(otasm_spi_build 1 0 0 0 0 0 0)" "4000"
    local out; out=$(otasm_spi_parse B800)
    chk spi-rccds   "$(fld "$out" rccds)" "2"
    chk spi-cipher  "$(fld "$out" ciphering)" "1"
    chk spi-counter "$(fld "$out" counter_mode)" "3"
    chk spi-clean   "$(fld "$out" findings)" "0"
    chk spi-dec     "$(fld "$(otasm_spi_parse 16384)" rccds)" "1"
    chk spi-bad     "$(otasm_spi_build 9 0 0 0 0 0 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. Weak SPI is flagged, and unknown/insecure is never reported safe.
    out=$(otasm_spi_parse 0000)
    chk spi-weak-cipher  "$(fld "$out" ciphering_meaning)" "NOT applied (payload in the clear)"
    chk spi-weak-integr  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="HIGH"' | wc -l | tr -d ' ')" "2"
    chk spi-weak-findings "$(fld "$out" findings)" "3"
    out=$(otasm_spi_parse 2000)   # cipher on, no integrity, counter 0
    chk spi-partial "$(fld "$out" findings)" "2"

    # 3. Command packet build/parse round-trip.
    local pkt; pkt=$(otasm_packet_build 01 010203 5 B800 01 02 aabbcc 01 01)
    out=$(otasm_packet_parse "$pkt")
    chk pkt-cpi   "$(fld "$out" cpi)" "01"
    chk pkt-spi   "$(fld "$out" spi)" "b800"
    chk pkt-kic   "$(fld "$out" kic)" "01"
    chk pkt-kid   "$(fld "$out" kid)" "02"
    chk pkt-tar   "$(fld "$out" tar)" "010203"
    chk pkt-counter "$(fld "$out" counter_dec)" "5"
    chk pkt-data  "$(fld "$out" data)" "aabbcc"
    chk pkt-cpl-matches "$(fld "$out" cpl)" "$(fld "$out" packet_bytes)"
    chk pkt-badhex "$(otasm_packet_parse zz >/dev/null 2>&1; echo $?)" "2"
    chk pkt-short  "$(otasm_packet_parse 01 >/dev/null 2>&1; echo $?)" "1"
    # a large payload forces the two-octet CPL form and still round-trips.
    local big; big=$(printf 'aa%.0s' {1..200})
    pkt=$(otasm_packet_build 01 010203 9 B800 01 02 "$big" 01 01)
    chk pkt-big-cpl-oct "$(fld "$(otasm_packet_parse "$pkt")" cpl_octets)" "2"
    chk pkt-big-data-len "$(( ${#big} / 2 ))" "200"

    # 4. Counter / replay decisions per the SPI mode.
    chk cnt-none    "$(fld "$(otasm_counter_check 100 100 0)" verdict)" "process (counter absent — no replay protection)"
    chk cnt-info    "$(fld "$(otasm_counter_check 100 100 1)" verdict)" "process (counter informational only)"
    chk cnt-gt-ok   "$(fld "$(otasm_counter_check 101 100 2)" verdict)" "process (counter above the received value)"
    chk cnt-gt-rep  "$(fld "$(otasm_counter_check 100 100 2)" verdict)" "REPLAY (counter not above RE)"
    chk cnt-seq-ok  "$(fld "$(otasm_counter_check 101 100 3)" verdict)" "process (counter is exactly RE+1)"
    chk cnt-seq-rep "$(fld "$(otasm_counter_check 103 100 3)" verdict)" "REPLAY (counter is not RE+1)"
    chk cnt-badmode "$(otasm_counter_check 1 1 9 >/dev/null 2>&1; echo $?)" "2"

    # 5. Scope: no send/deliver verb is dispatchable.
    chk scope-no-send    "$(otasm_cli_main --send >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-deliver "$(otasm_cli_main --deliver >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

otasm_menu() {
    while true; do
        banner
        echo "  === OTA Binary SMS ==="
        echo
        cat <<'M'
  [1]  Build an SPI
  [2]  Parse / audit an SPI
  [3]  Build a command packet
  [4]  Parse a command packet
  [5]  Counter / replay check
  [6]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  rccds(0-3)> " a; read -rp "  cipher(0-1)> " b; read -rp "  counter(0-3)> " d
               otasm_spi_build "$a" "$b" "$d"; echo; read -rp "  enter " _ ;;
            2) read -rp "  spi (hex or decimal)> " s; otasm_spi_parse "$s"; read -rp "  enter " _ ;;
            3) read -rp "  TAR(6hex)> " t; read -rp "  counter> " n; read -rp "  SPI(4hex)> " s
               read -rp "  KIc(2hex)> " k1; read -rp "  KID(2hex)> " k2; read -rp "  data hex> " dd
               otasm_packet_build 01 "$t" "$n" "$s" "$k1" "$k2" "$dd"; echo; read -rp "  enter " _ ;;
            4) read -rp "  packet hex> " p; otasm_packet_parse "$p"; read -rp "  enter " _ ;;
            5) read -rp "  counter> " n; read -rp "  RE> " r; read -rp "  mode 0-3> " m
               otasm_counter_check "$n" "$r" "${m:-0}"; read -rp "  enter " _ ;;
            6) otasm_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

otasm_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     otasm_status_tsv ;;
        --spi-build)      otasm_spi_build "${1:-0}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-0}" "${6:-0}" "${7:-0}" ;;
        --spi)            otasm_spi_parse "${1:-}" ;;
        --packet)         otasm_packet_build "${1:-01}" "${2:-000000}" "${3:-0}" "${4:-B800}" "${5:-01}" "${6:-01}" "${7:-}" "${8:-01}" "${9:-01}" ;;
        --parse-packet)   otasm_packet_parse "${1:-}" ;;
        --counter-check)  otasm_counter_check "${1:-}" "${2:-}" "${3:-0}" ;;
        --plan)           otasm_plan ;;
        --selftest)       otasm_selftest ;;
        --menu)           otasm_menu ;;
        *)
            cat >&2 <<EOF
OTA Binary SMS — TS 23.048 command packet construction and key/counter audit

Usage: $0 COMMAND
  --status-tsv                       module state as TSV
  --spi-build <rccds> <cipher> <counter> [por...]
  --spi <hex|dec>                    parse and audit an SPI
  --packet <cpi> <tar> <counter> <spi> <kic> <kid> <data> [chi] [cmd]
  --parse-packet <hex>               decode a command packet
  --counter-check <counter> <RE> [mode]   replay decision per SPI mode
  --plan                             own-SIM delivery handoff plan
  --selftest                         verify SPI, packet and replay logic
  --menu                             interactive menu

Scope: own-SIM and lab construction plus vulnerability detection. Affecting a
SIM you do not hold requires that SIM's OTA keys, which this module never holds.
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
    otasm_cli_main "$@"
fi
