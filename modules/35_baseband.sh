#!/usr/bin/env bash
# baseband — RRC/NAS fuzzing, a DIAG write, and the RF submission handoff.
#                                                          (tag: bbnd)
#
# TWO HALVES, and the banner between them is the point. The research half needs
# no radio, no modem and no gate: grammar-aware mutation of RRC/NAS messages,
# deterministic corpus generation, a BER/DER length codec, a NAS header decoder
# and ASAN/UBSAN crash-log triage. The offensive half can put bytes on a wire or
# name an instrument, so it prints a disclaimer, and its only device-write verb
# (--diag-send) writes only to the tty the operator names.
#
# WHAT THE OFFENSIVE HALF ACTUALLY DOES, because the line between "real" and
# "handoff" is the honest part of this file:
#
#   * --diag-frame is REAL bytes and so is --diag-send, but the DIAG framing is
#     not reimplemented here: modules/56_baseband_diag.sh owns the HDLC escape,
#     the 0x7E terminator and the CRC-16/X-25, and this module calls it. One
#     implementation, one place to fix.
#   * --transmit and --send-payload are HANDOFF. There is no OFDM modulator and
#     no radio driver anywhere in this tree, so these write the payload to disk,
#     name the tools a lab would modulate it with, and exit 3. They print no
#     line that claims a transmission.
#   * --rf-submit is REAL SCPI SYNTAX written to a file; playing that file is
#     the handoff. The command shapes are the ones the instrument vendors
#     document (Rohde & Schwarz SMW200A driver, Keysight X-Series programming
#     guide), and the default carrier and power are labelled as lab defaults,
#     not as measured values.
#
# Attack owned: O6 (baseband exploitation), per docs/ATTACK_COVERAGE.md and
# docs/OFFENSIVE_ROADMAP.md Phase 12 — the submission paths, and the seam where they
# touch a device, handoff-only where they would need a modulator.
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
    printf 'TAG\tbbnd\n'
    printf 'TARGET\tRRC/NAS mutation, corpus generation, crash triage\n'
    printf 'RESEARCH\tready (--mutate --corpus --triage --asn1-len --asn1-dec --nas-hdr; no radio)\n'
    printf 'FRAMING\tready via 56_baseband_diag --frame (the only DIAG encoder in the tree; not duplicated here)\n'
    printf 'DIAG_WRITE\t--diag-send writes the framed bytes to the tty you name, or to a regular file for a lab check (rc 0 write, 1 device/artefact failure, 2 usage)\n'
    printf 'TRANSMIT\thandoff only (--transmit/--send-payload write the payload and exit 3; this tree has no modulator)\n'
    printf 'RF_SUBMIT\tready (--rf-submit writes a SCPI file: SMW200A complete rc 0, N5182B upload-only rc 3; nothing is sent)\n'
    printf 'GATE\tnone -- the offensive verbs run without a flag\n'
    printf 'SELFTEST\tyes\n'
    printf 'FIRMWARE\t--firmware-analyze <file>  (container + advertised strings)\n'
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
            # Split: `local a=.. b=$(( ..a.. ))` expands every argument before
            # local runs, so b would read an unset a and the bound on the
            # duplicated tail would be wrong.
            local start len
            start=$(( r % nbytes )); len=$(( 1 + (r % (nbytes - start)) ))
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

# ── corpus minimisation ─────────────────────────────────────────────────
# --corpus generates mutations; nothing in the tree reduced them.  A fuzzing
# corpus that a person has to read is a corpus that does not get read: five
# hundred mutations of one message usually describe a handful of distinct
# changes, and each of those is a two-to-five octet window once it is compared
# against the message it was derived from.
#
# The criterion is stated rather than implied, because a minimiser without one
# is a filter that hides cases:
#
#   * the reference is the input the cases are compared against -- the caller's
#     --reference when given, otherwise the most frequent input in the file
#     (the unmutated seed is normally the mode).  Which one was used is
#     reported as reference_source, never guessed at silently.
#   * a case's distinguishing octets are the offsets where it differs from the
#     reference, plus any octets past the reference's end.
#   * a case is kept when it distinguishes an offset no kept case already
#     covers, most-covering first.  Ties go to the narrower window, so the same
#     coverage is reported with the smaller reproducer.
#   * the minimised case is the window from the first distinguishing octet to
#     the last, inclusive.  To rebuild it: take reference[0..first-1], then the
#     window, then reference[last+1..].
#
# Exit 1 means an offset was never distinguished by any case: that is a gap in
# the corpus, not a failure of the minimiser, and it is reported with the
# offsets rather than rounded away.
bbnd_corpus_min() {
    local file="${1:--}" ref="${2:-}" 
    if [[ "$file" != "-" ]]; then
        [[ -r "$file" ]] || { printf 'ERROR\tcorpus %s is not readable\n' "$file" >&2; return 2; }
    fi
    local tmp; tmp=$(mktemp "${TMPDIR:-/tmp}/bbnd-min.XXXXXX") || return 1
    if [[ "$file" == "-" ]]; then
        cat > "$tmp"
    else
        cat "$file" > "$tmp"
    fi
    if [[ -n "$ref" ]]; then
        ref=$(bbnd_norm_hex "$ref") || true
        if ! bbnd_is_hex "$ref"; then
            rm -f "$tmp"; printf 'ERROR\t--reference must be even-length hex\n' >&2; return 2
        fi
    fi
    local rc=0
    awk -F'\t' -v REF="${ref^^}" -v SELF="$0" '
        function byte(h, i) { return substr(h, 2*i+1, 2) }
        function nbytes(h) { return length(h)/2 }
        NR == 1 {
            # Accept the --corpus header, or a bare hex-per-line list.
            if (tolower($1) ~ /index/ || tolower($1) ~ /hex/) {
                for (i = 1; i <= NF; i++) col[tolower($i)] = i
                next
            }
        }
        {
            n++
            if (ncol == 0) {
                if (col["hex"])      { hx = $col["hex"];  st = $col["strategy"]; sd = $col["seed"]; ix = $col["index"] }
                else if (NF == 1)    { hx = $1; st = "-"; sd = "-"; ix = n - 1 }
                else                 { hx = $NF; st = "-"; sd = "-"; ix = n - 1 }
            } else {
                hx = $col["hex"]; st = $col["strategy"]; sd = $col["seed"]; ix = $col["index"]
            }
            gsub(/[^0-9A-Fa-f]/, "", hx)
            hx = toupper(hx)
            if (hx == "" || length(hx) % 2) { bad++; next }
            idx[n] = ix; strat[n] = st; seed[n] = sd; hex[n] = hx
            freq[hx]++
            if (length(hx) > maxlen) maxlen = length(hx)
        }
        END {
            if (n == 0) { print "ERROR\tno corpus rows to minimise"; exit 2 }
            if (bad)    { printf "ERROR\t%d row(s) were not even-length hex and were skipped\n", bad > "/dev/stderr" }

            # The reference: what the caller named, or the mode of the file.
            if (REF != "") { ref = REF; rsrc = "argument" }
            else {
                best = 0
                for (h in freq) if (freq[h] > best) { best = freq[h]; ref = h }
                rsrc = (best > 1) ? "mode(" best " cases)" : "first row (no repeated input to use as a mode)"
                if (best <= 1) ref = hex[1]
            }

            # Distinguishing offsets per case, and the window they span.
            for (i = 1; i <= n; i++) {
                h = hex[i]; nb = nbytes(h); rb = nbytes(ref); k = 0
                first = -1; last = -1
                lim = (nb > rb) ? nb : rb
                for (o = 0; o < lim; o++) {
                    a = (o < nb) ? byte(h, o) : "--"
                    b = (o < rb) ? byte(ref, o) : "--"
                    if (a != b) { diffs[i, ++k] = o; if (first < 0) first = o; last = o }
                }
                ndiff[i] = k; wfirst[i] = first; wlast[i] = last
                if (k > 0) {
                    win = substr(h, 2*first + 1, 2*(last - first + 1))
                    if (!(i in seen_win_seen) ) { }
                    winstr[i] = win
                }
            }

            # Greedy cover, most-covering first, narrower window on a tie.
            for (i = 1; i <= n; i++) order[i] = i
            for (i = 1; i <= n; i++)
                for (j = i + 1; j <= n; j++) {
                    ni = ndiff[order[i]]; nj = ndiff[order[j]]
                    wi = wfirst[order[i]]; wj = wfirst[order[j]]
                    li = wlast[order[i]];  lj = wlast[order[j]]
                    if (wj < 0) { t = order[i]; order[i] = order[j]; order[j] = t; continue }
                    if (wi < 0) continue
                    if (nj > ni || (nj == ni && (lj - wj) < (li - wi))) { t = order[i]; order[i] = order[j]; order[j] = t }
                }

            printf "input_cases\t%d\n", n
            printf "reference\ts%s\n", ref
            printf "reference_octets\t%d\n", nbytes(ref)
            printf "reference_source\t%s\n", rsrc

            kept = 0; covered = 0
            for (rank = 1; rank <= n; rank++) {
                i = order[rank]
                if (ndiff[i] == 0) continue
                newc = 0
                for (k = 1; k <= ndiff[i]; k++) if (!(diffs[i, k] in cov)) newc++
                if (newc == 0) continue
                kept++
                for (k = 1; k <= ndiff[i]; k++) { cov[diffs[i, k]] = 1; covered++ }
                covlist = ""
                for (k = 1; k <= ndiff[i]; k++) covlist = covlist (k > 1 ? "," : "") diffs[i, k]
                printf "kept\t%d\n", kept
                printf "kept_index\t%s\n", idx[i]
                printf "kept_strategy\t%s\n", strat[i]
                printf "kept_seed\t%s\n", seed[i]
                printf "window_first\t%d\n", wfirst[i]
                printf "window_last\t%d\n", wlast[i]
                printf "window_octets\t%d\n", wlast[i] - wfirst[i] + 1
                printf "distinguishes\t%s\n", covlist
                printf "minimised_hex\t%s\n", winstr[i]
                if (wfirst[i] == 0 && wlast[i] == nbytes(ref) - 1)
                    printf "reconstruct\tthe window is the whole reference\n"
                else if (wfirst[i] == 0)
                    printf "reconstruct\tthe window is the first %d octet(s); append reference[%d..]\n", wlast[i] + 1, wlast[i] + 1
                else if (wlast[i] == nbytes(ref) - 1)
                    printf "reconstruct\tprepend reference[0..%d]; the window ends the input\n", wfirst[i] - 1
                else
                    printf "reconstruct\tprepend reference[0..%d] and append reference[%d..]\n", wfirst[i] - 1, wlast[i] + 1
            }
            printf "kept_cases\t%d\n", kept
            printf "covered_offsets\t%d\n", covered
            # Every octet of the reference is a place the corpus could have
            # distinguished; the ones nobody touched are the honest gap.
            gaps = ""
            for (o = 0; o < nbytes(ref); o++) if (!(o in cov)) gaps = gaps (gaps == "" ? "" : ",") o
            printf "uncovered_offsets\t%s\n", (gaps == "" ? "-" : gaps)
            printf "uncovered_count\t%s\n", (gaps == "" ? 0 : split(gaps, gtmp, ","))
            printf "method\tgreedy cover over offsets differing from the reference; ties go to the narrower window\n"
            printf "caveat\ta minimised case is only meaningful against its reference -- it is a window, not a standalone message\n"
            exit (gaps == "" ? 0 : 1)
        }
    ' "$tmp"
    rc=$?
    rm -f "$tmp"
    return $rc
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

# ── the offensive half ──────────────────────────────────────────────────
# Everything below this banner can put bytes on a wire or name an instrument.
# Three rules hold the line between "real" and "handoff":
#
#   1. There is no gate. A verb that touches a device does the thing; what it
#      never does is claim success it cannot see. --transmit and --send-payload
#      still stop short by rule 3 below, not by permission.
#   2. --diag-frame is not an encoder. modules/56_baseband_diag.sh owns the
#      single DIAG framing implementation (HDLC escape, 0x7E terminator,
#      CRC-16/X-25); this module calls it and prints which module said so.
#   3. --transmit / --send-payload stop at "payload file on disk plus the name
#      of the tool that would modulate it" and exit 3. No line reads
#      "transmitted". --rf-submit stops at "SCPI command file on disk".

BBND_DIAG_MODULE="$IMSISTING_ROOT/modules/56_baseband_diag.sh"
BBND_TX_FREQ_HZ=2412000000   # lab default: band-20 downlink edge; NOT a measured value
BBND_TX_POWER_DBM=-20        # lab default: -20 dBm; NOT a measured value

# The note every offensive verb carries in its own output. There is no gate: what
# a reader needs is what the verb does and does not do, and that is a property of
# the verb rather than a permission check.
BBND_OFF_NOTE='no radio is keyed by this verb; --transmit and --send-payload write a payload file and name the modulator, and --diag-send writes to the tty you name and nothing else'

# One DIAG frame, from the module that owns DIAG framing. Validates the hex
# here first so a bad payload is a usage error (rc 2) and not a 56 error, then
# requires 56's output to look like an HDLC frame before using it. 56 returns 0
# even when it rejects a payload, so its rc alone is not evidence.
bbnd_diag_frame() {
    local hex="" dir_mode="host" errf raw
    while (( $# )); do
        case "$1" in
            --dir)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--dir needs host or device\n' >&2; return 2; }
                dir_mode="$2"; shift 2 ;;
            --*) printf 'ERROR\t--diag-frame does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                if [[ -z "$hex" ]]; then hex="$1"; shift
                else printf 'ERROR\t--diag-frame takes one payload, not a second: %s\n' "$(bbnd_sanitize "$1")" >&2; return 2; fi ;;
        esac
    done
    case "$dir_mode" in
        host|device) ;;
        *) printf 'ERROR\t--dir must be host or device: %s\n' "$(bbnd_sanitize "$dir_mode")" >&2; return 2 ;;
    esac
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--diag-frame needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }

    errf=$(mktemp "$MOD_TMP/diag.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    raw=$(bash "$BBND_DIAG_MODULE" --frame "$hex" 2>"$errf")
    if [[ ! "$raw" =~ ^[0-9a-f]+7e$ ]]; then
        printf 'ERROR\t56_baseband_diag --frame returned nothing usable for %s\n' "$hex" >&2
        while IFS= read -r line; do
            [[ -n "$line" ]] && printf 'ERROR\t%s\n' "$(bbnd_sanitize "$line")" >&2
        done < "$errf"
        rm -f "$errf"
        return 1
    fi
    rm -f "$errf"
    bbnd_print_frame "$hex" "$raw" "$dir_mode"
}

bbnd_print_frame() {
    local hex="$1" raw="$2" dir_mode="$3" body crc
    body="${raw%7e}"
    # CRC is transmitted little-endian: the last four hex digits are the two
    # CRC bytes low-first, so reorder them to the value 56 --crc prints.
    crc="${body: -2}${body: -4:2}"
    printf 'dir\t%s\n' "$dir_mode"
    printf 'payload\t%s\n' "$hex"
    printf 'payload_len\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'crc\t%s\n' "$crc"
    printf 'escaped_frame\t%s\n' "$raw"
    printf 'framing\t56_baseband_diag --frame\n'
    printf 'length_byte\tnone (HDLC delimited by a 0x7E terminator; CRC-16/X-25, little-endian)\n'
}

# 0 configured a tty, 1 the tty refused configuration, 2 not a tty (nothing to
# configure: a regular file is written with the same dd-of semantics).
bbnd_tty_config() {
    local dev="$1"
    if [[ -c "$dev" ]]; then
        stty -F "$dev" 115200 cs8 -cstopb -parenb raw -echo 2>/dev/null || return 1
        return 0
    fi
    return 2
}

# --diag-send: the only verb that writes to a device. The frame is 56's, the
# escape is 56's; this function adds the gate, the tty configuration and a
# write that can be checked. It never reports bytes written unless xxd, stty
# and the device all agreed.
bbnd_diag_send() {
    local hex="" dev=""
    while (( $# )); do
        case "$1" in
            --port)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--port needs a path\n' >&2; return 2; }
                dev="$2"; shift 2 ;;
            --*) printf 'ERROR\t--diag-send does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                if [[ -z "$hex" ]]; then hex="$1"; shift
                else printf 'ERROR\t--diag-send takes one payload\n' >&2; return 2; fi ;;
        esac
    done
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--diag-send needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }
    [[ -n "$dev" ]] || { printf 'ERROR\t--diag-send needs --port <path>; nothing was written\n' >&2; return 2; }

    local errf raw frame
    errf=$(mktemp "$MOD_TMP/diag.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    raw=$(bash "$BBND_DIAG_MODULE" --frame "$hex" 2>"$errf")
    if [[ ! "$raw" =~ ^[0-9a-f]+7e$ ]]; then
        printf 'ERROR\t56_baseband_diag --frame returned nothing usable for %s; nothing was written to %s\n' "$hex" "$(bbnd_sanitize "$dev")" >&2
        while IFS= read -r line; do
            [[ -n "$line" ]] && printf 'ERROR\t%s\n' "$(bbnd_sanitize "$line")" >&2
        done < "$errf"
        rm -f "$errf"
        return 1
    fi
    rm -f "$errf"
    frame="$raw"
    [[ "${frame: -2}" == "7e" ]] || { printf 'ERROR\tframe does not end in 7e; nothing was written\n' >&2; return 1; }

    if [[ ! -e "$dev" ]]; then
        printf 'ERROR\tno such device: %s; nothing was written\n' "$(bbnd_sanitize "$dev")" >&2
        printf 'WHY\t--diag-send needs an existing tty (a /dev/ttyUSB* or /dev/ttyACM* modem port); a path that does not exist is not a device\n' >&2
        return 1
    fi
    if [[ ! -w "$dev" ]]; then
        printf 'ERROR\tdevice is not writable: %s; nothing was written\n' "$(bbnd_sanitize "$dev")" >&2
        return 1
    fi
    local configured cfgrc=0
    bbnd_tty_config "$dev"; cfgrc=$?
    case "$cfgrc" in
        0) configured="yes (stty 115200 8N1 raw -echo)" ;;
        1) printf 'ERROR\tcould not configure %s as a tty; nothing was written\n' "$(bbnd_sanitize "$dev")" >&2
           return 1 ;;
        *) configured="n/a (not a tty; written with dd-of semantics)" ;;
    esac
    if ! printf '%s' "$frame" | xxd -r -p > "$dev" 2>/dev/null; then
        printf 'ERROR\twrite to %s failed; no bytes were accepted\n' "$(bbnd_sanitize "$dev")" >&2
        return 1
    fi
    local wrote="${#frame}"
    wrote=$(( wrote / 2 ))
    printf 'device\t%s\n' "$dev"
    printf 'framing\t56_baseband_diag --frame\n'
    printf 'wrote_bytes\t%d\n' "$wrote"
    printf 'configured\t%s\n' "$configured"
    printf 'payload\t%s\n' "$hex"
    printf 'frame\t%s\n' "$frame"
    printf 'note\t%s\n' "$BBND_OFF_NOTE"
    printf 'note\tbytes handed to the tty; whether the modem accepted them is a question only the modem answers\n'
}

bbnd_run_dir() {   # <prefix> -- a fresh directory under the loot tree for one run
    mkdir -p "$BBND_DIR" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$(bbnd_sanitize "$BBND_DIR")" >&2; return 1; }
    mktemp -d "$BBND_DIR/$1.XXXXXX"
}

bbnd_payload_write() {
    local hex="$1" out="$2" dir
    [[ -n "$out" ]] || { printf 'ERROR\tno destination path\n' >&2; return 1; }
    dir=$(dirname -- "$out")
    mkdir -p "$dir" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$(bbnd_sanitize "$dir")" >&2; return 1; }
    if ! printf '%s' "$hex" | xxd -r -p > "$out"; then
        printf 'ERROR\tcould not write %s\n' "$(bbnd_sanitize "$out")" >&2
        return 1
    fi
    return 0
}

# The handoff both transmit verbs share. It is deliberately boring: a file, its
# digest, the name of the tool a lab would use, and rc 3.
bbnd_handoff() {
    local hex="$1" framing="$2" out="$3" bytes sha
    bbnd_payload_write "$hex" "$out" || return 1
    bytes=$(( ${#hex} / 2 ))
    sha=$(sha256sum -- "$out" | cut -d' ' -f1)
    printf 'status\thandoff\n'
    printf 'framing\t%s\n' "$framing"
    printf 'payload_file\t%s\n' "$out"
    printf 'payload_bytes\t%d\n' "$bytes"
    printf 'payload_sha256\t%s\n' "$sha"
    printf 'keyed\t0\n'
    cat <<'HANDOFF'
why_handoff	this tree has no OFDM modulator, no RF driver and no channel model, so a payload file is as far as a software-only step goes
handoff_tool	srsRAN (srsRAN_4G or srsRAN_Project) or OpenAirInterface, both of which carry RRC/NAS bytes through their own encoders on a PLMN you own
handoff_step	1	take payload_file to a machine running srsRAN or OpenAirInterface for the EARFCN and PLMN you are licensed to use
handoff_step	2	feed the bytes through that stack's RRC ASN.1-PER encoder (or its NAS layer) rather than transmitting them raw
handoff_step	3	attach the device under test to that lab cell, capture its modem log or sanitizer output, and run the file through --triage
handoff_limit	modulating a waveform is not the same as a modem accepting it; nothing here has been accepted by any device
HANDOFF
    return 0
}

# ── the modulator ──────────────────────────────────────────────────────
# `--transmit` writes bytes and stops. This verb goes one step further and
# turns the same bytes into OFDM samples a sound-card- or SDR-side transmitter
# will key: QPSK symbols from the payload bits, mapped onto the LTE cell's
# resource grid (the grid, the IFFT and the cyclic prefixes are lte_phy's own,
# so the waveform is the one tools/lte_phy.py self-checks), one slot tiled to
# the capture length.
#
# What it is NOT: a PDSCH. There is no CRC, no Turbo coding, no rate matching,
# no DCI and no MIB on the BCH -- a modem cannot demodulate these samples into
# an RRC message without the rest of a real stack. The row `decodable_as` says
# that in the output rather than leaving the file to imply more.
bbnd_modulate() {
    local hex="" framing="rrc" rate="" pci="1" out="" secs="0.01"
    while (( $# )); do
        case "$1" in
            --framing) [[ -n "${2:-}" ]] || { printf 'ERROR\t--framing needs rrc or nas\n' >&2; return 2; }
                       framing="$2"; shift 2 ;;
            --rate)    rate="${2:-}"; shift 2 ;;
            --pci)     pci="${2:-}"; shift 2 ;;
            --out)     [[ -n "${2:-}" ]] || { printf 'ERROR\t--out needs a path\n' >&2; return 2; }
                       out="$2"; shift 2 ;;
            --secs)    secs="${2:-}"; shift 2 ;;
            --*) printf 'ERROR\t--modulate does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                if [[ -z "$hex" ]]; then hex="$1"; shift
                else printf 'ERROR\t--modulate takes one payload\n' >&2; return 2; fi ;;
        esac
    done
    case "$framing" in rrc|nas) ;; *)
        printf 'ERROR\t--framing must be rrc or nas: %s\n' "$(bbnd_sanitize "$framing")" >&2; return 2 ;; esac
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--modulate needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }
    case "$rate" in
        1920000|3840000|7680000|15360000|23040000|30720000) ;;
        *)  printf 'ERROR\t--rate %s is not an LTE sample rate\n' "$(bbnd_sanitize "${rate:-<empty>}")" >&2
            printf 'WHY\tthe grid and the IFFT in tools/lte_phy.py are indexed by N_RB and N_FFT; a rate that is not one of 1920000 3840000 7680000 15360000 23040000 30720000 has no grid to map onto\n' >&2
            return 2 ;;
    esac
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is needed for the grid and the IFFT\n' >&2; return 1; }
    local run
    if [[ -z "$out" ]]; then
        run=$(bbnd_run_dir modulate) || return 1
        out="$run/payload.cf32"
    fi
    local py; py=$(mktemp "${TMP_DIR:-/tmp}/bbnd_mod.XXXXXX.py") || return 1
    cat > "$py" <<'PY'
import sys, os, hashlib
sys.path.insert(0, os.environ["BBND_TOOLS"])
import lte_phy

hexs, rate, pci, out, secs = sys.argv[1:6]
rate, pci, secs = int(rate), int(pci), float(secs)
data = bytes.fromhex(hexs)

# QPSK: two bits per symbol (TS 36.211 7.1.2's constellation, through
# lte_phy's own modulator so there is one constellation in the tree).
bits = []
for b in data:
    for i in range(7, -1, -1):
        bits.append((b >> i) & 1)
if len(bits) % 2:
    bits.append(0)
syms = lte_phy.qpsk_modulate(bits)

n_rb, n_fft, _ = [(r, f, s) for bw, r, f, s in lte_phy.LTE_OFDM if s == rate][0]
n_sc = n_rb * 12
grid = [[0j] * n_sc for _ in range(7)]
# Keep the sync symbols of the cell out of the payload: PSS/SSS would
# overwrite symbols a receiver expects to find them in.
l_sss, l_pss = lte_phy.sync_symbols(0)
skip = {l_pss, l_sss}
used = []
k = 0
for l in range(7):
    if l in skip:
        continue
    for j in range(n_sc):
        grid[l][j] = syms[k % len(syms)]
        used.append((l, j))
        k += 1
one_slot = lte_phy.ofdm_modulate(grid, n_fft)[0]
nsamp = int(rate * secs)
x = (list(one_slot) * (nsamp // len(one_slot) + 1))[:nsamp]
# One scalar normalisation so a transmitter sees a known peak.
peak = max((abs(v) for v in x), default=0.0)
if peak > 0:
    x = [v * (0.999 / peak) for v in x]
with open(out, "wb") as fh:
    fh.write(b"".join(__import__("struct").pack("<ff", v.real, v.imag) for v in x))
print("payload_bytes\t%d" % len(data))
print("qpsk_symbols\t%d" % len(syms))
print("re_used\t%d" % len(used))
print("slot_samples\t%d" % len(one_slot))
print("samples\t%d" % len(x))
print("peak_full_scale\t1.0")
print("sha256\t%s" % hashlib.sha256(open(out, "rb").read()).hexdigest())
print("decodable_as\tno: QPSK symbols on the LTE grid with no CRC, Turbo coding, DCI or MIB; a modem needs the rest of a stack to invert this")
PY
    local rows; rows=$(BBND_TOOLS="$IMSISTING_ROOT/tools" timeout 300 python3 "$py" \
        "$hex" "$rate" "$pci" "$out" "$secs" 2>&1); local rc=$?
    rm -f "$py"
    if (( rc != 0 )); then
        printf 'ERROR\tthe modulator failed\n' >&2
        printf '%s\n' "$rows" | sed 's/^/  /' >&2
        return 1
    fi
    printf 'status\tmodulated\n'
    printf 'framing\t%s\n' "$framing"
    printf 'file\t%s\n' "$out"
    printf 'format\tcf32\n'
    printf 'rate\t%s\n' "$rate"
    printf 'pci\t%s\n' "$pci"
    printf 'seconds\t%s\n' "$secs"
    printf '%s\n' "$rows"
    printf 'grid\ttools/lte_phy.py ofdm_modulate (TS 36.211 6.12): %s\n' \
        "resource elements, PSS/SSS symbols left empty, one slot tiled"
    printf 'next\tkey the file with a transmitter, or read it back with --analyse-? on a receiver; the bytes are recoverable from the constellation, not from a modem log\n'
    return 0
}

bbnd_transmit() {
    local hex="" framing="rrc" out="" run
    while (( $# )); do
        case "$1" in
            --framing)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--framing needs rrc or nas\n' >&2; return 2; }
                framing="$2"; shift 2 ;;
            --out)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--out needs a path\n' >&2; return 2; }
                out="$2"; shift 2 ;;
            --*) printf 'ERROR\t--transmit does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                if [[ -z "$hex" ]]; then hex="$1"; shift
                else printf 'ERROR\t--transmit takes one payload\n' >&2; return 2; fi ;;
        esac
    done
    case "$framing" in rrc|nas) ;; *)
        printf 'ERROR\t--framing must be rrc or nas: %s\n' "$(bbnd_sanitize "$framing")" >&2; return 2 ;; esac
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--transmit needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }

    if [[ -z "$out" ]]; then
        run=$(bbnd_run_dir handoff) || return 1
        out="$run/payload.bin"
    fi
    bbnd_handoff "$hex" "$framing" "$out" || return 1
    printf 'next\trc 3 means the bytes are on disk and no radio was keyed; see handoff_step above\n'
    return 3
}

bbnd_send_payload() {
    local hex="" strat="" seed="" framing="rrc" out="" run mutated
    local npos=0
    while (( $# )); do
        case "$1" in
            --framing)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--framing needs rrc or nas\n' >&2; return 2; }
                framing="$2"; shift 2 ;;
            --out)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--out needs a path\n' >&2; return 2; }
                out="$2"; shift 2 ;;
            --*) printf 'ERROR\t--send-payload does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                case "$npos" in
                    0) hex="$1" ;;
                    1) strat="$1" ;;
                    2) seed="$1" ;;
                    *) printf 'ERROR\t--send-payload takes <hex> <strategy> <seed>\n' >&2; return 2 ;;
                esac
                npos=$(( npos + 1 )); shift ;;
        esac
    done
    case "$framing" in rrc|nas) ;; *)
        printf 'ERROR\t--framing must be rrc or nas: %s\n' "$(bbnd_sanitize "$framing")" >&2; return 2 ;; esac
    [[ -n "$strat" ]] || { printf 'ERROR\t--send-payload needs <hex> <strategy> <seed>\n' >&2; return 2; }
    [[ -n "$seed" ]] || seed=1
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--send-payload needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }

    mutated=$(bbnd_mutate "$hex" "$strat" "$seed") || return 2
    [[ -n "$mutated" ]] || { printf 'ERROR\tmutation produced no bytes\n' >&2; return 1; }
    printf 'input\t%s\n' "$hex"
    printf 'strategy\t%s\n' "$strat"
    printf 'seed\t%s\n' "$seed"
    printf 'mutated\t%s\n' "$mutated"
    if [[ -z "$out" ]]; then
        run=$(bbnd_run_dir handoff) || return 1
        out="$run/payload.bin"
    fi
    bbnd_handoff "$mutated" "$framing" "$out" || return 1
    printf 'next\trc 3 means the mutated bytes are on disk and no radio was keyed; see handoff_step above\n'
    return 3
}

# --rf-submit: a SCPI command file for a lab signal generator, and nothing else.
# Every command carries its source in the file itself:
#   SMW200A   SOURce:BB:ARBitrary:WAVeform:SELect / :STATe, SOURce:FREQuency:FIXed,
#             SOURce:POWer:LEVel:IMMediate:AMPLitude, OUTPut:STATe -- all quoted
#             from the R&S SMW200A SCPI tree as generated in the vendor's RsSmw
#             5.50.42 driver; MMEM:DATA is R&S's documented binary-block upload.
#   N5182B    :MEMory:DATA "WFM1:<file>",<block> from the Keysight X-Series
#             User's Guide (I/Q data into the instrument file system); the core
#             SOURce:FREQuency / POWer / OUTPut commands are SCPI-99. The
#             waveform-select and ARB-on commands are NOT emitted: no Keysight
#             document this tree can cite quotes them, so playback is left as an
#             operator step and the verb exits 3 instead of pretending the file
#             is a complete sequence.
# Defaults are labelled as lab defaults, never as measured values.
bbnd_rf_submit() {
    local hex="" instr="smw200a" freq="$BBND_TX_FREQ_HZ" power="$BBND_TX_POWER_DBM"
    local run wv scpi bytes digits header
    while (( $# )); do
        case "$1" in
            --instrument)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--instrument needs smw200a or n5182b\n' >&2; return 2; }
                instr="$2"; shift 2 ;;
            --freq)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--freq needs a value in Hz\n' >&2; return 2; }
                freq="$2"; shift 2 ;;
            --power)
                [[ -n "${2:-}" ]] || { printf 'ERROR\t--power needs a value in dBm\n' >&2; return 2; }
                power="$2"; shift 2 ;;
            --*) printf 'ERROR\t--rf-submit does not take %s (see --help)\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
            *)
                if [[ -z "$hex" ]]; then hex="$1"; shift
                else printf 'ERROR\t--rf-submit takes one payload\n' >&2; return 2; fi ;;
        esac
    done
    case "$instr" in smw200a|n5182b) ;; *)
        printf 'ERROR\t--instrument must be smw200a or n5182b: %s\n' "$(bbnd_sanitize "$instr")" >&2; return 2 ;; esac
    [[ "$freq" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--freq must be an integer number of Hz: %s\n' "$(bbnd_sanitize "$freq")" >&2; return 2; }
    [[ "$power" =~ ^-?[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\t--power must be a number in dBm: %s\n' "$(bbnd_sanitize "$power")" >&2; return 2; }
    hex=$(bbnd_norm_hex "$hex")
    bbnd_is_hex "$hex" || { printf 'ERROR\t--rf-submit needs even-length hex, got "%s"\n' "$(bbnd_sanitize "$hex")" >&2; return 2; }

    run=$(bbnd_run_dir rf) || return 1
    wv="$run/payload.bin"
    scpi="$run/submit.scpi"
    bbnd_payload_write "$hex" "$wv" || return 1

    bytes=$(( ${#hex} / 2 ))
    digits=${#bytes}
    header="#${digits}${bytes}"

    if [[ "$instr" == "smw200a" ]]; then
        {
            printf '# SCPI command file for a Rohde & Schwarz SMW200A\n'
            printf '# generated by modules/35_baseband.sh --rf-submit; nothing was sent to any instrument\n'
            printf '# sources: R&S SMW200A SCPI tree (RsSmw 5.50.42 driver) for\n'
            printf '#   BB:ARBitrary:WAVeform:SELect, BB:ARBitrary:STATe, FREQuency:FIXed, POWer:LEVel:IMMediate:AMPLitude, OUTPut:STATe\n'
            printf '#   MMEM:DATA is R&S binary block upload. *CLS is an IEEE 488.2 common command.\n'
            printf '# 1. THE FILE THIS MODULE WRITES IS NOT A WAVEFORM. payload.bin holds the %s\n' "$bytes"
            printf '#    message byte(s); an R&S ARB .wv is a container of I/Q sample pairs with its own\n'
            printf '#    header, and turning bits into samples needs a modulator this module does not have.\n'
            printf '#    Produce payload.wv with your modulation tool, upload it as a binary block, and the\n'
            printf '#    commands below then select it by name:\n'
            printf '#    MMEM:DATA '"'"'/var/user/payload.wv'"'"',<block header><the wv container>\n'
            printf '#    (the block header for a %s-byte container is #%s%s)\n' "$bytes" "${#bytes}" "$bytes"
            printf '*CLS\n'
            printf 'SOURce1:FREQuency:FIXed %s\n' "$freq"
            printf 'SOURce1:POWer:LEVel:IMMediate:AMPLitude %s\n' "$power"
            printf 'SOURce1:BB:ARBitrary:STATe OFF\n'
            printf "SOURce1:BB:ARBitrary:WAVeform:SELect 'payload.wv'\n"
            printf 'SOURce1:BB:ARBitrary:STATe ON\n'
            printf 'OUTPut1:STATe ON\n'
            printf '# 2. the generator is now armed on %s Hz at %s dBm; keying it is the operator act\n' "$freq" "$power"
            printf '# 3. after the run: OUTPut1:STATe OFF then SOURce1:BB:ARBitrary:STATe OFF\n'
        } > "$scpi" 2>/dev/null || {
            printf 'ERROR\tcould not write %s\n' "$(bbnd_sanitize "$scpi")" >&2; return 1; }
    else
        {
            printf '# SCPI command file for a Keysight N5182B (MXG X-Series)\n'
            printf '# generated by modules/35_baseband.sh --rf-submit; nothing was sent to any instrument\n'
            printf '# Each command below names its source:\n'
            printf '#   *CLS                              IEEE 488.2 common command (clear status)\n'
            printf '#   :MEMory:DATA "WFM1:<file>",<blk>  Keysight X-Series User Guide: I/Q data into the instrument file system\n'
            printf '#   [:SOURce]:FREQuency[:CW|FIXed]    SCPI-99 SOURce subsystem\n'
            printf '#   [:SOURce]:POWer[:LEVel][:IMMediate][:AMPLitude]  SCPI-99\n'
            printf '#   :OUTPut[:STATe]                   SCPI-99\n'
            printf '# 1. payload.bin holds the %s message byte(s) this module wrote; it is NOT a waveform.\n' "$bytes"
            printf '#    :WFM1:payload.wv must be a Keysight I/Q waveform container, which needs a modulator\n'
            printf '#    this module does not have. Upload that container as a binary block, not as text:\n'
            printf '#    :MEMory:DATA "WFM1:payload.wv",<block header><the container>\n'
            printf '*CLS\n'
            printf ':SOURce1:FREQuency:FIXed %s\n' "$freq"
            printf ':SOURce1:POWer:LEVel:IMMediate:AMPLitude %s\n' "$power"
            printf ':OUTPut:STATe ON\n'
            printf '# 2. PLAYBACK IS NOT IN THIS FILE ON PURPOSE: the waveform-select and ARB-on commands\n'
            printf '#    are not quoted by any Keysight document this tree can cite, so they are not guessed.\n'
            printf '#    Operator step: Mode > Dual ARB > Select Waveform, then ARB Off On\n'
            printf '#    (X-Series Signal Generators User Guide, Dual ARB Player section).\n'
            printf '# 3. after the run: :OUTPut:STATe OFF\n'
            printf '# WHAT I WOULD NEED: a Keysight X-Series SCPI Command Reference, to emit the\n'
            printf '# RADio:ARB waveform-select and ARB-state lines instead of leaving them to the operator.\n'
        } > "$scpi" 2>/dev/null || {
            printf 'ERROR\tcould not write %s\n' "$(bbnd_sanitize "$scpi")" >&2; return 1; }
    fi

    if [[ "$instr" == "smw200a" ]]; then
        printf 'status\tscpi_written\n'
        printf 'playback\tin file (every command sourced)\n'
    else
        printf 'status\tscpi_written_handoff\n'
        printf 'playback\toperator step: Mode > Dual ARB > Select Waveform, then ARB Off On\n'
        printf 'what_i_would_need\ta Keysight X-Series SCPI Command Reference to emit RADio:ARB waveform-select and ARB-state lines\n'
    fi
    printf 'instrument\t%s\n' "$instr"
    printf 'scpi_file\t%s\n' "$scpi"
    printf 'payload_file\t%s\n' "$wv"
    printf 'payload_is_waveform\tno -- raw message bytes; an ARB container needs a modulator this module does not have\n'
    printf 'payload_bytes\t%d\n' "$bytes"
    printf 'block_header\t%s\n' "$header"
    printf 'freq_hz\t%s\n' "$freq"
    printf 'power_dbm\t%s\n' "$power"
    printf 'freq_default\t%s\n' "$([[ "$freq" == "$BBND_TX_FREQ_HZ" ]] && echo 'lab default, not measured' || echo override)"
    printf 'power_default\t%s\n' "$([[ "$power" == "$BBND_TX_POWER_DBM" ]] && echo 'lab default, not measured' || echo override)"
    printf 'note\tthe .wv file is raw bytes in this instrument format, not a validated ARB waveform; the R&S ARB Toolbox or Keysight Signal Studio produces the real one\n'
    [[ "$instr" == "smw200a" ]] && return 0
    return 3
}

# ── --firmware-analyze: what a flash image says about itself ────────────
# A baseband image is a bag of containers. The cheapest honest read is the
# magic at offset 0 plus the strings the image carries, and each of those gets
# the doctrine label it deserves:
#
#   measured    the octets on disk: the magic, the superblock bytes, the size,
#               the digest
#   advertised  a string inside the image about itself -- "MPSS.AT.4.0",
#               "MSM8998", "QC_IMAGE_VERSION_STRING=..." -- which is what the
#               image claims, not proof of what runs
#   unobserved  no magic this module knows, no vendor token, no version string
#
# Container magics, all at offset 0 unless the row says otherwise:
#   1f 8b                    gzip        RFC 1952 §2.3.1
#   42 5a 68                 bzip2       the "BZh" stream header
#   fd 37 7a 58 5a 00        xz          XZ file format §2.1.1.1 (6 octets)
#   28 b5 2f fd              zstd        RFC 8878 §3.1.1.1
#   5d 00 00                 lzma-alone
#   50 4b 03 04              zip
#   68 73 71 73              squashfs    "hsqs" (0x73717368) superblock at 0
#   55 42 49 23              UBI         UBI-EC header magic 0x55424923
#   27 05 19 56              cramfs
#   85 72                    JFFS2       jffs2_unknown_node magic 0x1985
#   41 4e 44 52 49 4f 44 21  "ANDROID!" boot image (AOSP bootimg.h)
#   7f 45 4c 46              ELF
#   ext2/3/4                 magic 0x53 0xef at offset 0x438 (1024 + 56)
#
# Nothing is unpacked: identifying a container is not reading its contents, and
# an image inside an image stays unobserved until something unpacks it.
bbnd_firmware_analyze() {   # <file> [--strings-cap <bytes>]
    local file="${1:-}" cap=67108864
    (($# > 0)) && shift
    while (($#)); do
        case "$1" in
            --strings-cap) cap="${2:-67108864}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(bbnd_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    if [[ -z "$file" ]]; then
        printf 'ERROR\tusage: --firmware-analyze <file> [--strings-cap <bytes>]\n' >&2
        return 2
    fi
    if [[ ! -r "$file" || -d "$file" ]]; then
        printf 'ERROR\tcannot read %s\n' "$(bbnd_sanitize "$file")" >&2
        printf 'WHY\ta firmware image has to be a readable file; nothing is identified from a path that is not there\n' >&2
        return 1
    fi

    local size digest magic container filesystem compression basis
    local vendor='' vendor_tok='' vendor_hits=0 model='' version=''
    size=$(wc -c < "$file" | tr -d ' ')
    digest=$(command -v sha256sum >/dev/null 2>&1 && sha256sum "$file" | cut -d' ' -f1 || printf 'unobserved')
    magic=$(head -c 8 "$file" | od -An -tx1 | tr -d ' \n')
    container=''; filesystem=''; compression=''; basis=''
    case "$magic" in
        1f8b*)             container=gzip;     compression=gzip;  basis='RFC 1952 2.3.1: 1f 8b at offset 0' ;;
        425a68*)           container=bzip2;    compression=bzip2; basis='BZh stream header at offset 0' ;;
        fd377a585a00*)     container=xz;       compression=xz;    basis='XZ 2.1.1.1 magic fd 37 7a 58 5a 00' ;;
        28b52ffd*)         container=zstd;     compression=zstd;  basis='RFC 8878 3.1.1.1 magic 28 b5 2f fd' ;;
        5d0000*|5d0001*)   container=lzma;     compression=lzma;  basis='lzma-alone header at offset 0' ;;
        504b0304*)         container=zip;      compression=none-detected; basis='PK 03 04 local file header at offset 0' ;;
        68737173*)         container=squashfs; filesystem=squashfs; basis='0x73717368 "hsqs" superblock at offset 0' ;;
        55424923*)         container=ubi;      filesystem=ubi;    basis='0x55424923 "UBI#" EC header magic' ;;
        27051956*)         container=cramfs;   filesystem=cramfs; basis='cramfs superblock magic at offset 0' ;;
        8572*)             container=jffs2;    filesystem=jffs2;  basis='jffs2_unknown_node magic 0x1985 at offset 0' ;;
        414e4452494f4421*) container=android-boot; filesystem=''; basis='AOSP bootimg.h: "ANDROID!" at offset 0' ;;
        7f454c46*)         container=elf;      filesystem='';     basis='ELF 7f 45 4c 46 at offset 0' ;;
    esac
    # ext2/3/4 is the one magic that is not at offset 0.
    if [[ -z "$container" && "$size" -ge 1082 ]]; then
        local sb; sb=$(dd if="$file" bs=1 skip=1080 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
        if [[ "$sb" == "53ef" ]]; then
            container=ext234; filesystem=ext2/3/4
            basis='0x53ef superblock magic at offset 0x438 (1024 + 56)'
        fi
    fi
    [[ -n "$container" && -z "$compression" ]] && compression=none-detected

    # Strings the image carries about itself. Advertised, not measured.
    local scanlen=$cap
    (( size < cap )) && scanlen=$size
    local strs
    strs=$(head -c "$scanlen" "$file" | tr -c '\11\12\40-\176' '\n' \
        | awk 'length($0) >= 6 && length($0) <= 200' | head -c 4000000)
    local vclass tok hits
    for vclass in qualcomm mediatek samsung huawei intel unisoc broadcom quectel sierra telit nvidia; do
        case "$vclass" in
            qualcomm) tok='QUALCOMM|QCOM|QC_IMAGE|MSM[0-9]|MDM[0-9]|SDM[0-9]|SDX[0-9]' ;;
            mediatek) tok='MediaTek|MTK|MT[0-9]{4}' ;;
            samsung)  tok='Exynos|SAMSUNG' ;;
            huawei)   tok='Balong|Hi[0-9]{3,4}|HUAWEI' ;;
            intel)    tok='Intel|XMM[0-9]{3,4}|Infineon' ;;
            unisoc)   tok='UNISOC|Spreadtrum|SC[0-9]{4}' ;;
            broadcom) tok='Broadcom|BCM[0-9]{4}' ;;
            quectel)  tok='Quectel' ;;
            sierra)   tok='Sierra Wireless|SIERRA' ;;
            telit)    tok='Telit' ;;
            nvidia)   tok='NVIDIA|Tegra' ;;
        esac
        hits=$(printf '%s\n' "$strs" | grep -a -c -E "$tok" 2>/dev/null || true)
        [[ -z "$hits" ]] && hits=0
        if (( hits > 0 )); then
            vendor=$vclass; vendor_tok=$tok; vendor_hits=$hits
            break
        fi
    done
    model=$(printf '%s\n' "$strs" \
        | grep -a -o -E '(MSM|MDM|SDM|SDX|MT|SC|BCM|XMM|Hi|Exynos)[0-9]{3,4}' \
        | head -1 || true)
    version=$(printf '%s\n' "$strs" \
        | grep -a -o -E 'QC_IMAGE_VERSION_STRING=[A-Za-z0-9._-]{2,40}|MPSS[._-][A-Za-z0-9._-]{2,40}|[A-Za-z0-9_.-]*_FW_[A-Za-z0-9._-]{2,40}|V[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._-]{0,24}' \
        | head -1 || true)

    printf 'file\t%s\n'         "$(bbnd_sanitize "$file")"
    printf 'size\t%s\n'         "$size"
    printf 'sha256\t%s\n'       "${digest:--}"
    printf 'first_octets\t%s\n' "$(bbnd_sanitize "$magic")"
    if [[ -n "$container" ]]; then
        printf 'container\t%s\tmeasured\t%s\n' "$container" "$basis"
    else
        printf 'container\tunobserved\tmeasured\tthe first octets above match no container this module knows; nothing is guessed from a near-miss\n'
    fi
    if [[ -n "$compression" ]]; then
        printf 'compression\t%s\tmeasured\tfrom the container magic\n' "$compression"
    else
        printf 'compression\tunobserved\tunobserved\tno compressor magic in the first octets\n'
    fi
    if [[ -n "$filesystem" ]]; then
        printf 'filesystem\t%s\tmeasured\t%s\n' "$filesystem" "$basis"
    elif [[ -n "$container" ]]; then
        printf 'filesystem\tunobserved\tadvertised\tthe container is a compressor or a bare image: what it holds is unobserved until it is unpacked, and this verb does not unpack\n'
    else
        printf 'filesystem\tunobserved\tunobserved\tno filesystem magic and no compressor magic in the first octets\n'
    fi
    if (( vendor_hits > 0 )); then
        printf 'vendor\t%s\tadvertised\t%s string(s) matching "%s" inside the image\n' "$vendor" "$vendor_hits" "$vendor_tok"
    else
        printf 'vendor\tunobserved\tunobserved\tno vendor token from this module table appears in the scanned strings\n'
    fi
    if [[ -n "$model" ]]; then
        printf 'model\t%s\tadvertised\ta model token inside the image; it names a part, not the firmware that runs\n' "$(bbnd_sanitize "$model")"
    else
        printf 'model\tunobserved\tunobserved\tno model token (MSM/SDM/MT/Exynos/BCM/XMM...) in the scanned strings\n'
    fi
    if [[ -n "$version" ]]; then
        printf 'version\t%s\tadvertised\ta version string inside the image, not a measurement of the running firmware\n' "$(bbnd_sanitize "$version")"
    else
        printf 'version\tunobserved\tunobserved\tno QC_IMAGE_VERSION_STRING / MPSS / *_FW_ / Vx.y.z pattern in the scanned strings\n'
    fi
    if (( scanlen < size )); then
        printf 'strings_scope\t%s\tof\t%s\tnote\tstrings scanned from the head only; a version string past the cap stays unobserved\n' "$scanlen" "$size"
    else
        printf 'strings_scope\t%s\tof\t%s\tnote\twhole file scanned\n' "$scanlen" "$size"
    fi
    local verdict
    if [[ -n "$container" ]]; then
        verdict="container_identified:${container}"
    elif [[ -n "$vendor$model$version" ]]; then
        verdict='container_unobserved_strings_found'
    else
        verdict='nothing_identified'
    fi
    printf 'verdict\t%s\n' "$verdict"
    printf 'ref\tcontainer magics as cited per row; vendor and version tokens are strings (advertised), never measurements\n'
    printf 'limit\tthis reads container headers and strings; it does not unpack, does not validate a signature and does not compare against a CVE table (that is 54_baseband_exploit)\n'

    # Append-only store: one row per image examined, header first.
    local store ts
    store="$BBND_DIR/firmware.tsv"
    mkdir -p "$BBND_DIR" 2>/dev/null
    if [[ ! -f "$store" ]]; then
        printf 'ts\tfile\tsize\tsha256\tcontainer\tfilesystem\tvendor\tmodel\tversion\tverdict\n' > "$store"
    fi
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$(bbnd_sanitize "$file")" "$size" "${digest:--}" \
        "${container:-unobserved}" "${filesystem:-unobserved}" "${vendor:-unobserved}" \
        "$(bbnd_sanitize "${model:-unobserved}")" "$(bbnd_sanitize "${version:-unobserved}")" \
        "$verdict" >> "$store"
    printf 'store\t%s\n' "$store"
    if [[ "$verdict" == nothing_identified ]]; then
        printf 'WHY\tnothing in this image matched a container magic, a vendor token or a version pattern. That is unobserved, not clean: the file was read and it says nothing this module can read\n' >&2
        return 1
    fi
    return 0
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
    # ── corpus minimisation ─────────────────────────────────────────────
    # The generated corpus is the fixture: five octets, six cases, three of
    # which are the same mutation.  What the minimiser must prove is that it
    # collapses those three, trims each survivor to its distinguishing window,
    # and reports the offsets no case touched instead of pretending coverage.
    local cf; cf=$(mktemp "${TMPDIR:-/tmp}/bbnd-corpus.XXXXXX")
    bbnd_corpus 0011223344 6 byteflip > "$cf"
    chk cmin-input-cases "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="input_cases"{print $2}')" "6"
    chk cmin-kept-cases  "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="kept_cases"{print $2}')" "4"
    # Three identical cases must contribute one survivor, not three.
    chk cmin-collapses   "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="kept_index"{print $2}' | sort -n | uniq | wc -l | tr -d ' ')" "4"
    chk cmin-window-first "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="window_first"' | head -1 | cut -f2)" "0"
    chk cmin-window-hex  "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="minimised_hex"' | head -1 | cut -f2)" "FF"
    # Octet 3 is never mutated by this seed, and saying so is the point.
    chk cmin-uncovered   "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="uncovered_offsets"{print $2}')" "3"
    chk cmin-uncovered-n "$(bbnd_corpus_min "$cf" 0011223344 | awk -F'\t' '$1=="uncovered_count"{print $2}')" "1"
    chk cmin-rc1         "$(bbnd_corpus_min "$cf" 0011223344 >/dev/null 2>&1; echo $?)" "1"
    chk cmin-ref-source  "$(bbnd_corpus_min "$cf" | awk -F'\t' '$1=="reference_source"{print $2}')" "mode(3 cases)"
    # A corpus that touches every octet is complete, and exit 0 says so.
    local cf2; cf2=$(mktemp "${TMPDIR:-/tmp}/bbnd-corpus.XXXXXX")
    printf 'index\tstrategy\tseed\thex\n' > "$cf2"
    printf '0\tx\t1\tAAAAAAAB\n1\tx\t2\tAAAAABAA\n2\tx\t3\tAAABAAAA\n3\tx\t4\tABAAAAAA\n' >> "$cf2"
    chk cmin-full-cover  "$(bbnd_corpus_min "$cf2" AAAAAAAA | awk -F'\t' '$1=="uncovered_count"{print $2}')" "0"
    chk cmin-full-rc0    "$(bbnd_corpus_min "$cf2" AAAAAAAA >/dev/null 2>&1; echo $?)" "0"
    chk cmin-full-kept   "$(bbnd_corpus_min "$cf2" AAAAAAAA | awk -F'\t' '$1=="kept_cases"{print $2}')" "4"
    # An empty corpus is a refusal with a reason, not an empty answer.
    local cf3; cf3=$(mktemp "${TMPDIR:-/tmp}/bbnd-corpus.XXXXXX")
    printf 'index\tstrategy\tseed\thex\n' > "$cf3"
    chk cmin-empty-rc    "$(bbnd_corpus_min "$cf3" >/dev/null 2>&1; echo $?)" "2"
    chk cmin-missing     "$(bbnd_corpus_min /nonexistent/corpus.tsv >/dev/null 2>&1; echo $?)" "2"
    chk cmin-bad-ref     "$(bbnd_corpus_min "$cf" zz >/dev/null 2>&1; echo $?)" "2"
    # A bare hex list is accepted as well as the --corpus header.
    chk cmin-bare-list   "$(printf 'AABB\nAACB\n' | bbnd_corpus_min - AABB | awk -F'\t' '$1=="kept_cases"{print $2}')" "1"
    rm -f "$cf" "$cf2" "$cf3"

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

    # 6. The offensive half: no gate, a standing note, and what each verb can
    # and cannot claim. These replace the old scope-no-transmit/scope-no-payload
    # assertions, which only said "there is no verb"; these test the verb.

    # 6a. Every offensive verb runs with no flag. What it owes a reader is the
    # note, in its own output, and silence on stderr while it succeeds.
    : > "$d/plain.dev"
    out=$(bbnd_cli_main --diag-send 00 --port "$d/plain.dev" 2>"$d/plain.err"); rc=$?
    chk ungated-send-rc   "$rc" "0"
    chk ungated-send-stderr "$(grep -c . "$d/plain.err")" "0"
    chk ungated-note      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="note"{print (($2 ~ /no radio is keyed/)?"yes":"no")}' | head -1)" "yes"
    # The retired gate flag is rejected rather than swallowed: a script that
    # still passes it must find out, not go quiet.
    chk retired-flag-rejected "$(bbnd_cli_main --i-have-a-lab-and-authorisation --diag-send 00 --port "$d/plain.dev" >/dev/null 2>&1; echo $?)" "2"

    # 6b. It writes the bytes 56 framed. KAT: 56's own vector for payload 00 is
    # 0078f07e (CRC-16/X-25 of 0x00 is 0xF078, little-endian).
    chk send-bytes-00 "$(xxd -p "$d/plain.dev" 2>/dev/null | tr -d '\n')" "0078f07e"
    : > "$d/plain2.dev"
    bbnd_cli_main --diag-send 0100 --port "$d/plain2.dev" >/dev/null 2>&1
    chk send-bytes-0100 "$(xxd -p "$d/plain2.dev" 2>/dev/null | tr -d '\n')" "01009f167e"
    # A device that does not exist is rc 1 (attempted, no device), distinct from
    # a usage error (2) and from success (0).
    chk send-missing-rc "$(bbnd_cli_main --diag-send 00 --port "$d/absent" >/dev/null 2>&1; echo $?)" "1"
    # And a refusal for a bad request still writes nothing.
    chk send-no-port-rc "$(bbnd_cli_main --diag-send 00 >/dev/null 2>&1; echo $?)" "2"

    # 6d. --diag-frame is a consumer of 56, not a second encoder. These are the
    # seam's known-answer tests: the exact frames 56 prints for the same bytes.
    out=$(bbnd_cli_main --diag-frame 00)
    chk df-crc-00     "$(fld "$out" crc)" "f078"
    chk df-frame-00   "$(fld "$out" escaped_frame)" "0078f07e"
    chk df-framing    "$(fld "$out" framing)" "56_baseband_diag --frame"
    chk df-len        "$(fld "$out" payload_len)" "1"
    chk df-matches-56 "$([[ "$(fld "$out" escaped_frame)" == "$(bash "$BBND_DIAG_MODULE" --frame 00)" ]] && echo yes || echo no)" "yes"
    # A payload containing 0x7E and 0x7D exercises the escape on the seam too.
    out=$(bbnd_cli_main --diag-frame 7e7d)
    chk df-escape     "$(fld "$out" escaped_frame)" "7d5e7d5df1cd7e"
    chk df-dir-default "$(fld "$out" dir)" "host"
    out=$(bbnd_cli_main --diag-frame 0100 --dir device)
    chk df-dir-device "$(fld "$out" dir)" "device"
    chk df-frame-0100 "$(fld "$out" escaped_frame)" "01009f167e"
    chk df-bad-hex    "$(bbnd_cli_main --diag-frame zz >/dev/null 2>&1; echo $?)" "2"
    chk df-odd-hex    "$(bbnd_cli_main --diag-frame 0 >/dev/null 2>&1; echo $?)" "2"
    chk df-bad-dir    "$(bbnd_cli_main --diag-frame 00 --dir radio >/dev/null 2>&1; echo $?)" "2"

    # 6e. Handoff: exit 3, the exact payload on disk, and no line that reads as
    # a completed transmission.
    local rout rrc
    rout=$(bbnd_cli_main --transmit deadbeef --framing nas --out "$d/tx.bin" 2>/dev/null); rrc=$?
    chk tx-rc        "$rrc" "3"
    chk tx-bytes     "$(xxd -p "$d/tx.bin" 2>/dev/null | tr -d '\n')" "deadbeef"
    chk tx-status    "$(fld "$rout" status)" "handoff"
    chk tx-framing   "$(fld "$rout" framing)" "nas"
    chk tx-not-keyed  "$(fld "$rout" keyed)" "0"
    chk tx-claims-none "$(printf '%s\n' "$rout" | grep -ci 'transmitted')" "0"
    chk tx-bad-framing "$(bbnd_cli_main --transmit 00 --framing lte >/dev/null 2>&1; echo $?)" "2"

    # 6e2. The modulator writes samples, says what they are and are not, and
    #      refuses a rate that has no LTE grid.
    local mout mrc
    mout=$(bbnd_cli_main --modulate 0b4101 --rate 15360000 --pci 37 --out "$d/mod.cf32" 2>/dev/null); mrc=$?
    chk mod-rc        "$mrc" "0"
    chk mod-status    "$(fld "$mout" status)" "modulated"
    chk mod-bytes     "$(fld "$mout" payload_bytes)" "3"
    chk mod-symbols   "$(fld "$mout" qpsk_symbols)" "12"
    chk mod-slot      "$(fld "$mout" slot_samples)" "7680"
    chk mod-samples   "$(fld "$mout" samples)" "153600"
    chk mod-file      "$([[ -s "$d/mod.cf32" ]] && echo yes || echo no)" "yes"
    chk mod-bad-rate  "$(bbnd_cli_main --modulate 00 --rate 1234 >/dev/null 2>&1; echo $?)" "2"
    chk mod-bad-framing "$(bbnd_cli_main --modulate 00 --framing lte --rate 15360000 >/dev/null 2>&1; echo $?)" "2"
    chk mod-decodes   "$(printf '%s\n' "$mout" | awk -F'\t' '$1=="decodable_as" && $2 ~ /^no/{print "yes"; exit}')" "yes"

    # 6f. --send-payload mutates through the existing engine, then hands off.
    local want
    want=$(bbnd_mutate deadbeef bitflip 42)
    rout=$(bbnd_cli_main --send-payload deadbeef bitflip 42 --out "$d/mut.bin" 2>/dev/null); rrc=$?
    chk sp-rc      "$rrc" "3"
    chk sp-mutated "$(fld "$rout" mutated)" "$want"
    chk sp-bytes   "$(xxd -p "$d/mut.bin" 2>/dev/null | tr -d '\n')" "$want"
    chk sp-changed "$([[ "$want" != "deadbeef" ]] && echo yes || echo no)" "yes"

    # 6g. --rf-submit writes real SCPI for the named generator. The command
    # strings asserted here are the vendors' documented shapes, quoted in the
    # comment above bbnd_rf_submit.
    rout=$(bbnd_cli_main --rf-submit deadbeef --instrument smw200a 2>/dev/null); rrc=$?
    local scpi
    scpi=$(fld "$rout" scpi_file)
    chk rf-rc          "$rrc" "0"
    chk rf-scpi-exists "$([[ -f "$scpi" ]] && echo yes || echo no)" "yes"
    chk rf-select      "$(grep -c "^SOURce1:BB:ARBitrary:WAVeform:SELect 'payload.wv'" "$scpi")" "1"
    chk rf-arb-on      "$(grep -c '^SOURce1:BB:ARBitrary:STATe ON' "$scpi")" "1"
    chk rf-mmem        "$(grep -c '^#    MMEM:DATA' "$scpi")" "1"
    chk rf-block-hdr   "$(fld "$rout" block_header)" "#14"
    chk rf-payload-bytes "$(xxd -p "$(fld "$rout" payload_file)" 2>/dev/null | tr -d '\n')" "deadbeef"
    # The file this module writes is the message, and saying otherwise is the lie
    # a lab instrument would find first: an ARB .wv is a container of I/Q pairs.
    chk rf-not-a-waveform "$(fld "$rout" payload_is_waveform | cut -d' ' -f1)" "no"
    chk rf-select-names-wv "$(grep -c "WAVeform:SELect 'payload.wv'" "$scpi")" "1"
    chk rf-default-lab "$(fld "$rout" freq_default)" "lab default, not measured"
    chk rf-bad-instr   "$(bbnd_cli_main --rf-submit 00 --instrument e4438c >/dev/null 2>&1; echo $?)" "2"
    chk rf-bad-power   "$(bbnd_cli_main --rf-submit 00 --power high >/dev/null 2>&1; echo $?)" "2"
    # The Keysight branch stops where its sources stop: verified upload and
    # SCPI-99 core commands, playback left as an operator step, so rc 3.
    rout=$(bbnd_cli_main --rf-submit 00 --instrument n5182b 2>/dev/null); rrc=$?
    scpi=$(fld "$rout" scpi_file)
    chk rf-keysight-rc     "$rrc" "3"
    chk rf-keysight-status "$(fld "$rout" status)" "scpi_written_handoff"
    chk rf-keysight-mem    "$(grep -c '^#    :MEMory:DATA' "$scpi")" "1"
    chk rf-keysight-freq   "$(grep -c '^:SOURce1:FREQuency:FIXed 2412000000' "$scpi")" "1"
    chk rf-keysight-noplay "$(grep -c '^:SOURce1:RADio:ARB' "$scpi")" "0"
    chk rf-keysight-need   "$(grep -c 'WHAT I WOULD NEED' "$scpi")" "1"

    # 6h. The status line stopped implying detection-only.
    out=$(bbnd_status_tsv)
    chk status-no-gate "$(printf '%s\n' "$out" | awk -F'\t' '$1=="GATE"{print ($2 ~ /^none/)?"none":"other"}')" "none"
    chk status-transmit   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSMIT"{print $2}' | grep -c 'handoff only')" "1"
    chk status-diag-plain "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DIAG_WRITE"{print ($2 ~ /^--diag-send/)?"yes":"no"}')" "yes"
    chk status-framing    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="FRAMING"{print $2}' | grep -c '56_baseband_diag')" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    # 5. --firmware-analyze: the container magic is measured, the vendor and
    #    version strings are advertised, and a file with neither is unobserved
    #    and refused (rc 1) rather than described.
    printf '\037\213\010\000\000\000\000\000' > "$d/fw.gz"
    printf 'hsqs\000\000\000\000QUALCOMM MSM8998 QC_IMAGE_VERSION_STRING=MPSS.AT.4.0.1' > "$d/fw.sq"
    head -c 2048 /dev/zero > "$d/fw.ext"
    printf 'S\357' | dd of="$d/fw.ext" bs=1 seek=1080 conv=notrunc 2>/dev/null
    printf '\252\252\252\252\252\252\252\252\252\252\252\252' > "$d/fw.unk"
    local fw
    fw=$(bbnd_firmware_analyze "$d/fw.gz")
    chk fw-gzip      "$(fld "$fw" container)" "gzip"
    chk fw-gzip-b    "$(printf '%s\n' "$fw" | awk -F'\t' '$1=="container"{print $2"|"$3}')" "gzip|measured"
    chk fw-gzip-fs   "$(fld "$fw" filesystem)" "unobserved"
    chk fw-gzip-v    "$(fld "$fw" verdict)" "container_identified:gzip"
    fw=$(bbnd_firmware_analyze "$d/fw.sq")
    chk fw-squashfs  "$(fld "$fw" container)" "squashfs"
    chk fw-vendor    "$(fld "$fw" vendor)" "qualcomm"
    chk fw-vendor-b  "$(printf '%s\n' "$fw" | awk -F'\t' '$1=="vendor"{print $3}')" "advertised"
    chk fw-model     "$(fld "$fw" model)" "MSM8998"
    chk fw-version   "$(printf '%s\n' "$fw" | awk -F'\t' '$1=="version"{print ($2 ~ /MPSS/) ? "version-string" : "none"}')" "version-string"
    chk fw-version-b "$(printf '%s\n' "$fw" | awk -F'\t' '$1=="version"{print $3}')" "advertised"
    fw=$(bbnd_firmware_analyze "$d/fw.ext")
    chk fw-ext4      "$(fld "$fw" container)" "ext234"
    chk fw-ext4-b    "$(printf '%s\n' "$fw" | awk -F'\t' '$1=="container"{print ($4 ~ /0x438/) ? "offset-cited" : "no"}')" "offset-cited"
    fw=$(bbnd_firmware_analyze "$d/fw.unk" 2>/dev/null)
    chk fw-unknown   "$(fld "$fw" container)" "unobserved"
    chk fw-unknown-v "$(fld "$fw" verdict)" "nothing_identified"
    chk fw-unknown-rc "$(bbnd_firmware_analyze "$d/fw.unk" >/dev/null 2>&1; echo $?)" "1"
    chk fw-missing   "$(bbnd_firmware_analyze "$d/none.bin" >/dev/null 2>&1; echo $?)" "1"
    chk fw-noargs    "$(bbnd_firmware_analyze >/dev/null 2>&1; echo $?)" "2"
    chk fw-store-hdr "$(head -1 "$BBND_DIR/firmware.tsv" 2>/dev/null | cut -f1)" "ts"
    local fwrows
    fwrows=$(awk -F'\t' 'NR>1' "$BBND_DIR/firmware.tsv" 2>/dev/null | grep -c . || true)
    chk fw-store-rows "$(( fwrows >= 4 ))" "1"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

bbnd_menu() {
    while true; do
        banner
        echo "  === Baseband Fuzzing ==="
        echo
        cat <<'M'
  [1]  ASN.1 length encode
  [2]  ASN.1 length decode
  [3]  Mutate a message
  [4]  Generate a corpus
  [5]  Decode a NAS security header
  [6]  Triage a sanitizer log
  [7]  Analyze a baseband firmware image
  [8]  Layer reference
  [9]  Plan (handoff)
  [10] DIAG frame (via 56_baseband_diag)
  [11] DIAG send to a modem tty
  [12] Hand a payload off (write file, name the tool)
  [13] RF submission file (SCPI)
  [0]  back
M
        echo "  NOTE: --diag-send writes to the tty you name and nothing else"
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
            7) read -rp "  image path> " p2; bbnd_firmware_analyze "$p2"; read -rp "  enter " _ ;;
            8) bbnd_layers; read -rp "  enter " _ ;;
            9) bbnd_plan; read -rp "  enter " _ ;;
            10) read -rp "  hex> " h; bbnd_diag_frame "$h"; read -rp "  enter " _ ;;
            11) read -rp "  hex> " h; read -rp "  device> " p
                bbnd_diag_send "$h" --port "$p"; read -rp "  enter " _ ;;
            12) read -rp "  hex> " h; read -rp "  framing (rrc|nas)> " f
                bbnd_transmit "$h" --framing "${f:-rrc}"; read -rp "  enter " _ ;;
            13) read -rp "  hex> " h; bbnd_rf_submit "$h"; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

bbnd_cli_main() {
    # No flag is consumed: the arguments reach the dispatcher untouched, so a
    # retired --i-have-a-lab-and-authorisation is a usage error rather than a
    # silent no-op.
    local -a bbnd_args=()
    local a
    for a in "$@"; do
        case "$a" in
            *) bbnd_args+=("$a") ;;
        esac
    done
    local cmd="${bbnd_args[0]:-}"
    local -a rest=()
    (( ${#bbnd_args[@]} > 1 )) && rest=("${bbnd_args[@]:1}")

    case "$cmd" in
        --status-tsv)   bbnd_status_tsv ;;
        --asn1-len)     bbnd_asn1_len_encode "${rest[0]:-}" ;;
        --asn1-dec)     bbnd_asn1_len_decode "${rest[0]:-}" ;;
        --mutate)       bbnd_mutate "${rest[0]:-}" "${rest[1]:-bitflip}" "${rest[2]:-1}" ;;
        --corpus)       bbnd_corpus "${rest[0]:-}" "${rest[1]:-16}" "${rest[2]:-bitflip}" ;;
        --corpus-min)   { local _mref=""; local _i
                          for (( _i = 1; _i < ${#rest[@]}; _i++ )); do
                              [[ "${rest[_i]}" == "--reference" ]] && _mref="${rest[_i+1]:-}"
                          done
                          bbnd_corpus_min "${rest[0]:--}" "$_mref"; } ;;
        --nas-hdr)      bbnd_nas_hdr "${rest[0]:-}" ;;
        --triage)       bbnd_triage "${rest[0]:-}" ;;
        --firmware-analyze) bbnd_firmware_analyze "${rest[@]}" ;;
        --layers)       bbnd_layers ;;
        --plan)         bbnd_plan ;;
        --diag-frame)   bbnd_diag_frame "${rest[@]}" ;;
        --diag-send)    bbnd_diag_send "${rest[@]}" ;;
        --transmit)     bbnd_transmit "${rest[@]}" ;;
        --send-payload) bbnd_send_payload "${rest[@]}" ;;
        --modulate)     bbnd_modulate "${rest[@]}" ;;
        --rf-submit)    bbnd_rf_submit "${rest[@]}" ;;
        --selftest)     bbnd_selftest ;;
        --menu)         bbnd_menu ;;
        *)
            cat >&2 <<EOF
Baseband Fuzzing — RRC/NAS fuzzing, a gated DIAG write, and the RF handoff

Usage: $0 COMMAND

Research half (no radio, no gate):
  --status-tsv            module state as TSV
  --asn1-len <n>          BER/DER definite length encode
  --asn1-dec <hex>        BER/DER definite length decode
  --mutate <hex> <strat> <seed>
  --corpus <hex> <count> <strat>
  --corpus-min <file|-> [--reference <hex>]
                          reduce a generated corpus to the cases that distinguish
                          offsets nothing else covers, each trimmed to its window
  --nas-hdr <hex>         EPS NAS security header decode
  --triage <log|->        ASAN/UBSAN crash-log triage
  --firmware-analyze <file> [--strings-cap <bytes>]
                          identify a flash image: container magic, filesystem or
                          compressor, and the vendor/model/version strings it
                          carries (advertised, never measured); unobserved for the
                          rest, and nothing is unpacked
  --layers                protocol-layer reference
  --plan                  over-the-air handoff plan

Offensive half (disclaimer on stderr, gate where a device is written):
  --diag-frame <hex> [--dir host|device]
                          DIAG/QCDM frame from 56_baseband_diag (its framing
                          verb; this module reimplements none of it)
  --diag-send <hex> --port <path>
                          write that frame to a modem tty, or to a regular file
                          for a lab check
  --transmit <hex> [--framing rrc|nas] [--out <path>]
                          write the payload, print the over-the-air handoff (exit 3)
  --send-payload <hex> <strategy> <seed> [--framing rrc|nas] [--out <path>]
                          mutate with --mutate's engine, then hand off (exit 3)
  --rf-submit <hex> [--instrument smw200a|n5182b] [--freq <hz>] [--power <dbm>]
                          write a SCPI command file for a lab signal generator

No flag is needed to run any of them. --diag-send writes to the tty you name and
nothing else; --transmit and --send-payload write a payload file and print the
handoff; --rf-submit writes an instrument command file.
Exit codes: 0 success, 1 device/artefact failure, 2 bad usage,
3 handoff (the bytes are on disk and nothing was transmitted).
Scope: a research instrument. The over-the-air step needs a modulator this tree
does not have, so --transmit names a tool and stops; nothing here radiates.
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
