#!/usr/bin/env bash
# baseband — RRC/NAS fuzzing scaffolding, corpus generation and crash triage.
#
# SCOPE, first because it is the point: this is a research instrument, not a
# weapon. A working zero-click RCE against named production modem firmware is an
# offensive payload with no defensive framing and is not something this tree
# ships. What this module *does* build is the tooling baseband research actually
# runs on: grammar-aware mutation of RRC/NAS messages, deterministic corpus
# generation, a BER/DER length codec, and ASAN/UBSAN crash-log triage. Point it
# at a modem you own or a lab device; the over-the-air step is a handoff.
#
# Attack owned: O6 (baseband exploitation) research half, per
# docs/ATTACK_COVERAGE.md — probe or handoff, never a live payload.
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

MOD_TMP="$TMP_DIR/baseband"
BBND_DIR="$LOOT_DIR/baseband"
mkdir -p "$MOD_TMP" "$BBND_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

bbnd_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
BBND_F=()
bbnd_split() {
    BBND_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        BBND_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

bbnd_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
bbnd_is_hex() {
    local h; h=$(bbnd_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}

bbnd_status_tsv() {
    printf 'MODULE\tbaseband\n'
    printf 'TARGET\tRRC/NAS mutation, corpus generation, crash triage\n'
    printf 'TRANSMIT\tnone — this module emits no over-the-air payload\n'
    printf 'SELFTEST\tyes\n'
}

# ── BER/DER definite-length codec (X.690 §8.1.3) ────────────────────────
# Short form: lengths 0..127 are one octet, top bit clear.
# Long form:  first octet is 0x80|n followed by n big-endian length octets.
#   length 128   -> 81 80
#   length 255   -> 81 FF
#   length 256   -> 82 01 00
#   length 65535 -> 82 FF FF
#   length 65536 -> 83 01 00 00
bbnd_asn1_len_encode() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be a non-negative integer\n' >&2; return 2; }
    (( n <= 127 )) && { printf '%02X\n' "$(( n & 0xFF ))"; return 0; }
    if (( n <= 0xFF )); then printf '81%02X\n' "$(( n & 0xFF ))"
    elif (( n <= 0xFFFF )); then printf '82%02X%02X\n' "$(( (n >> 8) & 0xFF ))" "$(( n & 0xFF ))"
    elif (( n <= 0xFFFFFF )); then printf '83%02X%02X%02X\n' "$(( (n >> 16) & 0xFF ))" "$(( (n >> 8) & 0xFF ))" "$(( n & 0xFF ))"
    else printf 'ERROR\tlength %s exceeds the 3-octet definite form (16777215)\n' "$n" >&2; return 2
    fi
}

# decode: prints "len\tN" then "octets\tK" (K = length octets consumed).
bbnd_asn1_len_decode() {
    local h; h=$(bbnd_norm_hex "${1:-}")
    bbnd_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    local b0=$(( 16#${h:0:2} ))
    if (( (b0 & 0x80) == 0 )); then
        printf 'len\t%d\noctets\t1\n' "$b0"; return 0
    fi
    local n=$(( b0 & 0x7F ))
    (( n == 0 )) && { printf 'ERROR\tindefinite length (0x80) is not valid DER\n' >&2; return 1; }
    (( n > 4 )) && { printf 'ERROR\tlength-of-length %d too large\n' "$n" >&2; return 1; }
    (( ${#h} >= 2 + n*2 )) || { printf 'ERROR\ttruncated length field\n' >&2; return 1; }
    local v=0 i
    for (( i = 0; i < n; i++ )); do
        v=$(( (v << 8) | 16#${h:$(( 2 + i*2 )):2} ))
    done
    printf 'len\t%d\noctets\t%d\n' "$v" "$(( n + 1 ))"
}

# ── deterministic mutation engine ───────────────────────────────────────
# A 31-bit glibc LCG makes every corpus reproducible from its seed, so a crash
# can always be replayed from (seed, strategy, index).
bbnd_lcg() { printf '%d' "$(( (1103515245 * ${1:-0} + 12345) & 0x7FFFFFFF ))"; }

bbnd_byte_get() { printf '%d' "$(( 16#${1:$(( ${2:-0} * 2 )):2} ))"; }
bbnd_byte_set() {
    local h="$1" i="$2" v="$3"
    printf '%s%02x%s' "${h:0:$(( i * 2 ))}" "$(( v & 0xFF ))" "${h:$(( i * 2 + 2 ))}"
}

# mutate HEX STRATEGY SEED -> mutated hex on stdout
bbnd_mutate() {
    local hex; hex=$(bbnd_norm_hex "${1:-}")
    local strat="${2:-bitflip}" seed="${3:-1}"
    bbnd_is_hex "$hex" || { printf 'ERROR\tinput must be even-length hex\n' >&2; return 2; }
    [[ "$seed" =~ ^[0-9]+$ ]] || { printf 'ERROR\tseed must be numeric\n' >&2; return 2; }
    local n=${#hex} nbytes=$(( ${#hex} / 2 ))
    local r=$(( seed & 0x7FFFFFFF ))
    r=$(bbnd_lcg "$r")

    case "$strat" in
        bitflip)
            local bit=$(( r % (nbytes * 8) ))
            local pos=$(( bit / 8 )) mask=$(( 1 << (bit % 8) ))
            bbnd_byte_set "$hex" "$pos" "$(( $(bbnd_byte_get "$hex" "$pos") ^ mask ))" ;;
        byteflip)
            local pos=$(( r % nbytes ))
            bbnd_byte_set "$hex" "$pos" "$(( $(bbnd_byte_get "$hex" "$pos") ^ 0xFF ))" ;;
        nibbleflip)
            local pos=$(( r % nbytes )) v; v=$(bbnd_byte_get "$hex" "$pos")
            bbnd_byte_set "$hex" "$pos" "$(( v ^ (0xF << (4 * (r % 2))) ))" ;;
        boundary)
            local pos=$(( r % nbytes )) v=$(( r % 2 == 0 ? 0x00 : 0xFF ))
            bbnd_byte_set "$hex" "$pos" "$v" ;;
        truncate)
            (( nbytes < 2 )) && { printf '%s' "$hex"; return 0; }
            local keep=$(( 1 + (r % (nbytes - 1)) ))
            printf '%s' "${hex:0:$(( keep * 2 ))}" ;;
        extend)
            printf '%s%02x' "$hex" "$(( r & 0xFF ))" ;;
        duplicate)
            (( nbytes < 2 )) && { printf '%s%s' "$hex" "$hex"; return 0; }
            local start=$(( r % nbytes )) len=$(( 1 + (r % (nbytes - start)) ))
            printf '%s%s' "$hex" "${hex:$(( start * 2 )):$(( len * 2 ))}" ;;
        len-corrupt)
            # ASN.1-aware: overwrite the first length octet with a value that
            # disagrees with the actual body, which is the classic length-oracle
            # seed. 0x84 (length-of-length 4) is a favourite crash candidate.
            local v=$(( r % 2 == 0 ? 0x84 : 0x7F ))
            bbnd_byte_set "$hex" 0 "$v" ;;
        *)
            printf 'ERROR\tunknown strategy: %s\n' "$strat" >&2; return 2 ;;
    esac
}

bbnd_corpus() {
    local hex; hex=$(bbnd_norm_hex "${1:-}")
    local count="${2:-16}" strat="${3:-bitflip}"
    bbnd_is_hex "$hex" || { printf 'ERROR\tseed input must be even-length hex\n' >&2; return 2; }
    [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )) || { printf 'ERROR\tcount must be a positive integer\n' >&2; return 2; }
    printf 'index\tstrategy\tseed\thex\n'
    local i seed=1
    for (( i = 0; i < count; i++ )); do
        seed=$(bbnd_lcg "$seed")
        printf '%d\t%s\t%d\t%s\n' "$i" "$strat" "$seed" "$(bbnd_mutate "$hex" "$strat" "$seed")"
    done
}

# ── NAS security-header decode (TS 24.301 §9.3.1) ───────────────────────
# Octet 1: bits 8-5 security header type, bits 4-1 protocol discriminator.
#   PD 0x7 = EPS mobility management; 0x2 = EPS session management.
#   security header 0 = plain, 1/2 = integrity[-and-ciphered], 3/4 = new context.
bbnd_nas_hdr() {
    local h; h=$(bbnd_norm_hex "${1:-}")
    bbnd_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 2 )) || { printf 'ERROR\tNAS message too short for octet 1\n' >&2; return 1; }
    local b0=$(( 16#${h:0:2} ))
    local sec=$(( (b0 >> 4) & 0x0F )) pd=$(( b0 & 0x0F ))
    local pd_txt sec_txt
    case "$pd" in
        7) pd_txt="EPS mobility management" ;;
        2) pd_txt="EPS session management" ;;
        *) pd_txt="unknown (TS 24.007 protocol discriminator)" ;;
    esac
    case "$sec" in
        0) sec_txt="plain NAS" ;;
        1) sec_txt="integrity protected" ;;
        2) sec_txt="integrity protected and ciphered" ;;
        3) sec_txt="integrity protected with new EPS security context" ;;
        4) sec_txt="integrity protected and ciphered with new EPS security context" ;;
        *) sec_txt="reserved" ;;
    esac
    printf 'octet1\t%02X\npd\t%d\npd_meaning\t%s\nsecurity_header\t%d\nsecurity_meaning\t%s\n' \
        "$b0" "$pd" "$pd_txt" "$sec" "$sec_txt"
}

# ── crash triage ────────────────────────────────────────────────────────
bbnd_layers() {
    cat <<'EOF'
layer	protocol	typical_input
RRC	RRC (TS 36.331 / 38.331)	ASN.1 PER, the richest attack surface
NAS	EMM/ESM/5GMM (TS 24.301 / 24.501)	octet-aligned TLVs, length-oracle friendly
S1AP	NGAP/S1AP (TS 36.413 / 38.413)	ASN.1 APER over SCTP
RLC	RLC/MAC (TS 36.322 / 38.322)	byte-aligned headers, bitfields
EOF
}

# triage a sanitizer log: print "class\tcount". Reads a file or stdin.
bbnd_triage() {
    local input="${1:-}"
    local tmp
    if [[ -n "$input" ]]; then
        [[ -f "$input" ]] || { printf 'ERROR\tno such file: %s\n' "$input" >&2; return 1; }
        tmp="$input"
    else
        tmp=$(mktemp "$MOD_TMP/triage.XXXXXX")
        cat > "$tmp"
    fi
    local total=0
    local hbo sbo gbo uaf uninit segv ubsan abort sovf
    hbo=$(grep -c -i 'heap-buffer-overflow' "$tmp" 2>/dev/null || true)
    sbo=$(grep -c -i 'stack-buffer-overflow' "$tmp" 2>/dev/null || true)
    gbo=$(grep -c -i 'global-buffer-overflow' "$tmp" 2>/dev/null || true)
    uaf=$(grep -c -i 'use-after-free' "$tmp" 2>/dev/null || true)
    uninit=$(grep -c -iE 'use-of-uninitialized-value|uninitialized' "$tmp" 2>/dev/null || true)
    segv=$(grep -c -iE 'segmentation fault|SEGV' "$tmp" 2>/dev/null || true)
    ubsan=$(grep -c -iE 'runtime error:|UndefinedBehaviorSanitizer' "$tmp" 2>/dev/null || true)
    abort=$(grep -c -iE 'ABORTING|abort trap' "$tmp" 2>/dev/null || true)
    sovf=$(grep -c -i 'stack-overflow' "$tmp" 2>/dev/null || true)
    total=$(( hbo + sbo + gbo + uaf + uninit + segv + ubsan + abort + sovf ))
    printf 'class\tcount\n'
    (( hbo   )) && printf 'heap-buffer-overflow\t%d\n' "$hbo"
    (( sbo   )) && printf 'stack-buffer-overflow\t%d\n' "$sbo"
    (( gbo   )) && printf 'global-buffer-overflow\t%d\n' "$gbo"
    (( uaf   )) && printf 'use-after-free\t%d\n' "$uaf"
    (( uninit )) && printf 'use-of-uninitialized-value\t%d\n' "$uninit"
    (( sovf  )) && printf 'stack-overflow\t%d\n' "$sovf"
    (( segv  )) && printf 'segv\t%d\n' "$segv"
    (( ubsan )) && printf 'ubsan-runtime-error\t%d\n' "$ubsan"
    (( abort )) && printf 'abort\t%d\n' "$abort"
    (( total == 0 )) && printf 'none\t0\n'
    [[ -z "$input" ]] && rm -f "$tmp"
    return 0
}

bbnd_plan() {
    cat <<'EOF'
status	handoff
what	over-the-air fuzzing of a live modem's RRC/NAS stack
hardware	an SDR with transmit (USRP B210/X310, BladeRF, or a channel simulator) plus an owned modem under test
software	srsRAN UE/gNB for a controlled stack, or a vendor-provided crash-observable target
flow	1. generate the corpus here  2. feed it through the owned stack's decoder  3. collect sanitizer logs  4. run --triage
note	nothing is transmitted by this module; a crash against production firmware is not produced or shipped
EOF
}

bbnd_selftest() {
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
    export BBND_DIR="$d/loot/baseband"
    mkdir -p "$BBND_DIR"

    # 1. BER/DER length. Values are the X.690 §8.1.3 worked examples.
    chk len-0     "$(bbnd_asn1_len_encode 0)"       "00"
    chk len-127   "$(bbnd_asn1_len_encode 127)"     "7F"
    chk len-128   "$(bbnd_asn1_len_encode 128)"     "8180"
    chk len-255   "$(bbnd_asn1_len_encode 255)"     "81FF"
    chk len-256   "$(bbnd_asn1_len_encode 256)"     "820100"
    chk len-65535 "$(bbnd_asn1_len_encode 65535)"   "82FFFF"
    chk len-65536 "$(bbnd_asn1_len_encode 65536)"   "83010000"
    chk len-max   "$(bbnd_asn1_len_encode 16777215)" "83FFFFFF"
    chk len-neg   "$(bbnd_asn1_len_encode -1 >/dev/null 2>&1; echo $?)" "2"
    chk len-big   "$(bbnd_asn1_len_encode 16777216 >/dev/null 2>&1; echo $?)" "2"
    chk len-str   "$(bbnd_asn1_len_encode abc >/dev/null 2>&1; echo $?)" "2"
    # decode both directions, inside a long-form segment not just at the edge.
    chk dec-8180  "$(fld "$(bbnd_asn1_len_decode 8180)" len)" "128"
    chk dec-820100 "$(fld "$(bbnd_asn1_len_decode 820100)" len)" "256"
    chk dec-octets "$(fld "$(bbnd_asn1_len_decode 820100)" octets)" "3"
    chk dec-short "$(fld "$(bbnd_asn1_len_decode 7F)" len)" "127"
    chk dec-indef "$(bbnd_asn1_len_decode 80 >/dev/null 2>&1; echo $?)" "1"
    chk dec-trunc "$(bbnd_asn1_len_decode 82 >/dev/null 2>&1; echo $?)" "1"
    chk dec-badhex "$(bbnd_asn1_len_decode zz >/dev/null 2>&1; echo $?)" "2"

    # 2. NAS security header (TS 24.301 §9.3.1).
    local out
    out=$(bbnd_nas_hdr 07)
    chk nas-pd-07  "$(fld "$out" pd)" "7"
    chk nas-sec-07 "$(fld "$out" security_header)" "0"
    out=$(bbnd_nas_hdr 27)
    chk nas-pd-27  "$(fld "$out" pd)" "7"
    chk nas-sec-27 "$(fld "$out" security_header)" "2"
    out=$(bbnd_nas_hdr 02)
    chk nas-pd-esm "$(fld "$out" pd_meaning)" "EPS session management"
    chk nas-short  "$(bbnd_nas_hdr '' >/dev/null 2>&1; echo $?)" "2"

    # 3. Mutation is deterministic and actually mutates.
    local m1 m2 m3
    m1=$(bbnd_mutate deadbeef bitflip 42)
    m2=$(bbnd_mutate deadbeef bitflip 42)
    m3=$(bbnd_mutate deadbeef bitflip 43)
    chk mut-deterministic "$([[ "$m1" == "$m2" ]] && echo yes || echo no)" "yes"
    chk mut-differs-seed "$([[ "$m1" != "$m3" ]] && echo yes || echo no)" "yes"
    chk mut-changed-input "$([[ "$m1" != "deadbeef" ]] && echo yes || echo no)" "yes"
    chk mut-len-stable "$(( ${#m1} ))" "8"
    # truncate must not grow the input, and must stay valid hex.
    local t; t=$(bbnd_mutate deadbeef truncate 7)
    chk trunc-shrinks "$(( ${#t} < 8 ))" "1"
    chk trunc-even "$(( ${#t} % 2 ))" "0"
    local e; e=$(bbnd_mutate aa extend 1)
    chk extend-grows "$(( ${#e} > 2 ))" "1"
    # a length-corrupt seed sets the first octet and keeps the body.
    local lc; lc=$(bbnd_mutate 0481ffAABB len-corrupt 2)
    chk len-corrupt-body "${lc:2}" "81ffaabb"
    chk mut-bad-strat "$(bbnd_mutate deadbeef bogus 1 >/dev/null 2>&1; echo $?)" "2"
    chk mut-bad-hex   "$(bbnd_mutate xyz bitflip 1 >/dev/null 2>&1; echo $?)" "2"
    chk mut-bad-seed  "$(bbnd_mutate deadbeef bitflip x >/dev/null 2>&1; echo $?)" "2"

    # 4. Corpus: deterministic row count and reproducible rows.
    local c1 c2
    c1=$(bbnd_corpus 0011223344 8 byteflip)
    c2=$(bbnd_corpus 0011223344 8 byteflip)
    chk corpus-rows "$(printf '%s\n' "$c1" | tail -n +2 | wc -l | tr -d ' ')" "8"
    chk corpus-stable "$([[ "$c1" == "$c2" ]] && echo yes || echo no)" "yes"
    chk corpus-header "$(printf '%s\n' "$c1" | head -1)" "$(printf 'index\tstrategy\tseed\thex')"
    chk corpus-bad-count "$(bbnd_corpus 00 0 byteflip >/dev/null 2>&1; echo $?)" "2"

    # 5. Crash triage: positive signatures classify, negatives abstain.
    printf '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n' > "$d/c.log"
    printf 'runtime error: left shift of negative value\n' >> "$d/c.log"
    printf '==2==ERROR: AddressSanitizer: stack-buffer-overflow\n' >> "$d/c.log"
    out=$(bbnd_triage "$d/c.log")
    chk triage-hbo  "$(fld "$out" heap-buffer-overflow)" "1"
    chk triage-sbo  "$(fld "$out" stack-buffer-overflow)" "1"
    chk triage-ubsan "$(fld "$out" ubsan-runtime-error)" "1"
    chk triage-none "$(fld "$out" none)" ""
    printf 'all good, no crash\n' > "$d/clean.log"
    chk triage-clean "$(fld "$(bbnd_triage "$d/clean.log")" none)" "0"
    chk triage-missing "$(bbnd_triage "$d/nope.log" >/dev/null 2>&1; echo $?)" "1"
    # triage must not misclassify a plain 'error' word as a crash.
    printf 'some error happened\n' > "$d/e.log"
    chk triage-error-not-crash "$(fld "$(bbnd_triage "$d/e.log")" none)" "0"

    # 6. Scope assertion, behavioural: there is no transmit verb to dispatch.
    chk scope-no-transmit "$(bbnd_cli_main --transmit >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-payload  "$(bbnd_cli_main --send-payload >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

bbnd_menu() {
    while true; do
        banner
        echo "  === Baseband Research ==="
        echo
        cat <<'M'
  [1]  ASN.1 length encode
  [2]  ASN.1 length decode
  [3]  Mutate a message
  [4]  Generate a corpus
  [5]  Decode a NAS security header
  [6]  Triage a sanitizer log
  [7]  Layer reference
  [8]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  length> " n; bbnd_asn1_len_encode "$n"; read -rp "  enter " _ ;;
            2) read -rp "  hex> " h; bbnd_asn1_len_decode "$h"; read -rp "  enter " _ ;;
            3) read -rp "  hex> " h; read -rp "  strategy> " s; read -rp "  seed> " z
               bbnd_mutate "$h" "$s" "$z"; echo; read -rp "  enter " _ ;;
            4) read -rp "  seed hex> " h; read -rp "  count> " n; read -rp "  strategy> " s
               bbnd_corpus "$h" "$n" "$s"; read -rp "  enter " _ ;;
            5) read -rp "  nas hex> " h; bbnd_nas_hdr "$h"; read -rp "  enter " _ ;;
            6) read -rp "  log path> " p; bbnd_triage "$p"; read -rp "  enter " _ ;;
            7) bbnd_layers; read -rp "  enter " _ ;;
            8) bbnd_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

bbnd_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   bbnd_status_tsv ;;
        --asn1-len)     bbnd_asn1_len_encode "${1:-}" ;;
        --asn1-dec)     bbnd_asn1_len_decode "${1:-}" ;;
        --mutate)       bbnd_mutate "${1:-}" "${2:-bitflip}" "${3:-1}" ;;
        --corpus)       bbnd_corpus "${1:-}" "${2:-16}" "${3:-bitflip}" ;;
        --nas-hdr)      bbnd_nas_hdr "${1:-}" ;;
        --triage)       bbnd_triage "${1:-}" ;;
        --layers)       bbnd_layers ;;
        --plan)         bbnd_plan ;;
        --selftest)     bbnd_selftest ;;
        --menu)         bbnd_menu ;;
        *)
            cat >&2 <<EOF
Baseband Research — RRC/NAS mutation, corpus generation, crash triage

Usage: $0 COMMAND
  --status-tsv            module state as TSV
  --asn1-len <n>          BER/DER definite length encode
  --asn1-dec <hex>        BER/DER definite length decode
  --mutate <hex> <strat> <seed>
  --corpus <hex> <count> <strat>
  --nas-hdr <hex>         EPS NAS security header decode
  --triage <log|->        ASAN/UBSAN crash-log triage
  --layers                protocol-layer reference
  --plan                  over-the-air handoff plan
  --selftest              verify codecs and mutation, no radio needed
  --menu                  interactive menu

Scope: a research instrument. It mutates, generates corpora and triages crashes.
It emits no over-the-air payload; the fuzz step is a handoff to hardware you own.
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
    bbnd_cli_main "$@"
fi
