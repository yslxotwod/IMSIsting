#!/usr/bin/env bash
# tools/check-gtp-fuzz.sh -- referee for tools/gtp_fuzz.py's corpus.
#
# The corpus is built by modules/11_lte_core.sh's --gtp-fuzz verb from a seed.
# Its whole claim is that each case moves ONE field of the GTP header away from
# what TS 29.281 / TS 29.274 / TS 29.060 say and that the field a reader must
# notice is the one the plan names.  That claim is checkable without a radio and
# without our own code being the judge: generate the corpus, wrap every case in
# an IPv4/UDP datagram (text2pcap cannot frame a bare PDU, so the pcap is built
# by hand here), let tshark 4.2.2 dissect it, and compare what the dissector
# said against the spec-derived expectation for that case name.
#
# Each expectation below is either a fixed value the specification pins down or
# a named expert note tshark itself raises.  A passing run proves the case is
# exactly the deviation the plan claims -- not that the deviation is a
# vulnerability, which only a peer can show.
#
# Exit 0 every expectation held, 1 a mismatch, 2 usage or a missing tool.
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || exit 2
GEN="$ROOT/tools/gtp_fuzz.py"
TSHARK="${TSHARK:-$(command -v tshark 2>/dev/null || true)}"

[[ -f "$GEN" ]] || { printf 'check-gtp-fuzz: %s is missing\n' "$GEN" >&2; exit 2; }
[[ -n "$TSHARK" && -x "$TSHARK" ]] || {
    printf 'check-gtp-fuzz: tshark is missing; it is the referee here\n' >&2; exit 2; }
PY=$(command -v python3 2>/dev/null || true)
[[ -n "$PY" ]] || { printf 'check-gtp-fuzz: python3 is missing\n' >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gtp-fuzz-referee.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT

SEED="${SEED:-7}"
"$PY" "$GEN" --seed "$SEED" --pcap "$WORK/corpus.pcap" \
    --plan-tsv "$WORK/plan.tsv" >"$WORK/gen.txt" 2>&1 || {
    printf 'check-gtp-fuzz: the generator failed\n' >&2; sed -n '1,20p' "$WORK/gen.txt" >&2; exit 1; }

# ── what the dissector must say, case by case ────────────────────────────────
# Columns: case, field, expected.  field is one of the tshark fields below;
# "expert" means an error/warning note must be present, "expert-none" means the
# dissector must be silent, and "expert~TEXT" means the note must contain TEXT.
#
# Spec anchors, one per family:
#   TS 29.281 5.1     header layout, PT flag, message length, TEID
#   TS 29.281 5.2.1   extension header chain and its length octet
#   TS 29.281 7.1     Echo Request/Response on port 2152
#   TS 29.274 5.1     v2-C header, T flag, length field
#   TS 29.274 8.2/8.3 IE header (type/length/spare/criticality) and IMSI
#   TS 29.060 6.1/7.7 v1-C header and its mandatory fields
cat >"$WORK/expect.tsv" <<'EXPECT'
gtpu-control	proto	GTP
gtpu-control	message	0xff
gtpu-control	length	6
gtpu-control	expert-none	
gtpu-version-2	proto	UDP
gtpu-version-2	message	
gtpu-pt-zero	message	0xff
gtpu-pt-zero	teid	
gtpu-length-short	message	0xff
gtpu-length-short	length	4
gtpu-length-long	message	0xff
gtpu-length-long	length	22
gtpu-length-counts-eight	message	0xff
gtpu-length-counts-eight	length	14
gtpu-teid-zero	message	0xff
gtpu-teid-zero	teid	0x00000000
gtpu-sn-flag-no-sequence	expert	
gtpu-type-reserved	proto	UDP
gtpu-type-reserved	message	
gtpu-echo-length-8	message	0x01
gtpu-echo-length-8	length	12
gtpu-echo-no-flags	message	0x01
gtpu-echo-no-flags	length	4
gtpu-ext-honest	message	0xff
gtpu-ext-honest	length	12
gtpu-ext-honest	ext_next	0x40,0x00
gtpu-ext-honest	expert-none	
gtpu-ext-truncated-chain	message	0xff
gtpu-ext-truncated-chain	length	12
gtpu-ext-truncated-chain	ext_next	0x40,0x00
gtpu-ext-length-overrun	expert~should be 1	
gtpu-ext-loop	message	0xff
gtpu-ext-loop	length	28
gtpu-ext-loop	ext_next	0x40,0x00
gtpc2-control	message_type	32
gtpc2-control	msg_length	30
gtpc2-control	ie_types	1,73,2
gtpc2-version-1	message	0x20
gtpc2-version-1	message_type	
gtpc2-spare-octet	message_type	32
gtpc2-spare-octet	msg_length	13
gtpc2-spare-octet	ie_types	2
gtpc2-teid-without-t	message_type	32
gtpc2-teid-without-t	teid	
gtpc2-length-long	message_type	32
gtpc2-length-long	msg_length	64
gtpc2-length-long	expert	
gtpc2-imsi-overlong	message_type	32
gtpc2-imsi-overlong	ie_types	1,2
gtpc2-imsi-short	message_type	32
gtpc2-imsi-short	ie_types	1,2
gtpc2-imsi-padding	message_type	32
gtpc2-imsi-padding	expert~IMSI	
gtpc2-ebi-sixteen	message_type	32
gtpc2-ebi-sixteen	ie_types	73,2
gtpc2-ebi-zero	message_type	32
gtpc2-ebi-zero	ie_types	73,2
gtpc2-ie-length-past-end	message_type	32
gtpc2-ie-length-past-end	expert~length 200	
gtpc2-ie-zero-length	message_type	32
gtpc2-ie-zero-length	ie_types	2,1
gtpc2-unknown-ie-reject	message_type	32
gtpc2-unknown-ie-reject	ie_types	2,240
gtpc2-unknown-ie-ignore	message_type	32
gtpc2-unknown-ie-ignore	ie_types	2,240
gtpc2-criticality-reserved	message_type	32
gtpc2-criticality-reserved	ie_types	2,1
gtpc1-version-2	proto	GTPv2
gtpc1-version-2	message	
gtpc1-flag-without-sequence	message	0x10
gtpc1-flag-without-sequence	expert	
gtpc1-length-not-multiple	message	0x10
gtpc1-length-not-multiple	length	6
EXPECT

# One pass over the capture: the plan's case names, in frame order, alongside
# the fields the expectations use.  Frame N is case N: the generator writes one
# frame per case, in plan order, and the referee relies on that.
"$TSHARK" -r "$WORK/corpus.pcap" -T fields -E separator=';' \
    -e _ws.col.Protocol -e gtp.message -e gtp.length -e gtp.teid \
    -e gtp.ext_hdr.next -e gtpv2.message_type -e gtpv2.msg_length \
    -e gtpv2.teid -e gtpv2.ie_type -e _ws.expert.message \
    >"$WORK/fields.txt" 2>"$WORK/tshark.err" || {
    printf 'check-gtp-fuzz: tshark could not read the corpus\n' >&2
    sed -n '1,10p' "$WORK/tshark.err" >&2; exit 1; }

# Column numbers, 1-based, matching the -e order above.
col_of() {
    case "$1" in
        proto) printf '1' ;;
        message) printf '2' ;;
        length) printf '3' ;;
        teid) printf '4' ;;
        ext_next) printf '5' ;;
        message_type) printf '6' ;;
        msg_length) printf '7' ;;
        ie_types) printf '9' ;;
        *) printf '0' ;;
    esac
}

fail=0
checked=0
while IFS=$'\t' read -r case field expected; do
    [[ "$case" == '#'* || -z "$case" ]] && continue
    frame=$(awk -F'\t' -v c="$case" 'NR>1 && $3==c {print NR-1; exit}' "$WORK/plan.tsv")
    if [[ -z "$frame" ]]; then
        printf 'MISMATCH\t%s\tthe plan has no case with this name\n' "$case"
        fail=$((fail + 1)); continue
    fi
    line=$(sed -n "${frame}p" "$WORK/fields.txt")
    case "$field" in
        expert)
            got=$(printf '%s' "$line" | awk -F';' '{print $10}')
            [[ -n "$got" ]] || {
                printf 'MISMATCH\t%s\t%sthe dissector said nothing, so the case is not visibly malformed\n' \
                    "$case" "$field: "; fail=$((fail + 1)); continue; } ;;
        expert-none)
            got=$(printf '%s' "$line" | awk -F';' '{print $10}')
            [[ -z "$got" ]] || {
                printf 'MISMATCH\t%s\tthe dissector objected: %s\n' "$case" "$got"
                fail=$((fail + 1)); continue; } ;;
        expert~*)
            wants=${field#expert~}
            got=$(printf '%s' "$line" | awk -F';' '{print $10}')
            case "$got" in
                *"$wants"*) ;;
                *) printf 'MISMATCH\t%s\texpected a note containing %s, got: %s\n' \
                       "$case" "$wants" "${got:-nothing}"; fail=$((fail + 1)); continue ;;
            esac ;;
        *)
            n=$(col_of "$field")
            got=$(printf '%s' "$line" | awk -F';' -v n="$n" '{print $n}')
            if [[ "$field" == "proto" && "$got" == "$expected"* ]]; then
                checked=$((checked + 1)); continue
            fi
            if [[ "$got" != "$expected" ]]; then
                printf 'MISMATCH\t%s\t%s: expected %s, got %s\n' \
                    "$case" "$field" "${expected:-nothing}" "${got:-nothing}"
                fail=$((fail + 1)); continue
            fi ;;
    esac
    checked=$((checked + 1))
done <"$WORK/expect.tsv"

# Extension chains, refereed by the decoder that walks them.  Each row is a
# case and a string the decoder must print; "!" means it must NOT print it.
while IFS=$'\t' read -r case wants; do
    [[ -z "$case" ]] && continue
    hex=$(awk -F'\t' -v c="$case" 'NR>1 && $3==c {print $9; exit}' "$WORK/plan.tsv")
    [[ -n "$hex" ]] || { printf 'MISMATCH\t%s\tthe plan has no octets\n' "$case"; fail=$((fail + 1)); continue; }
    out=$(bash "$ROOT/modules/62_gtpu.sh" --parse "$hex" 2>&1)
    case "$wants" in
        !*)
            if [[ "$out" == *"${wants#!}"* ]]; then
                printf 'MISMATCH\t%s\tthe decoder printed %s, and must not\n' "$case" "${wants#!}"
                fail=$((fail + 1)); continue
            fi ;;
        *)
            if [[ "$out" != *"$wants"* ]]; then
                printf 'MISMATCH\t%s\tthe decoder did not print %s\n' "$case" "$wants"
                fail=$((fail + 1)); continue
            fi ;;
    esac
    checked=$((checked + 1))
done <<'CHAIN'
gtpu-ext-honest	extension_0_next	00
gtpu-ext-honest	!truncated
gtpu-ext-truncated-chain	extension_1	truncated
gtpu-ext-loop	extension_1_loop	
gtpu-ext-length-overrun	truncated
CHAIN

# The corpus must be deterministic: the same seed has to give the same bytes.
"$PY" "$GEN" --seed "$SEED" --pcap "$WORK/a.pcap" >/dev/null 2>&1
"$PY" "$GEN" --seed "$SEED" --pcap "$WORK/b.pcap" >/dev/null 2>&1
if ! cmp -s "$WORK/a.pcap" "$WORK/b.pcap"; then
    printf 'MISMATCH\tdeterminism\ttwo runs at seed %s differ\n' "$SEED"; fail=$((fail + 1))
else
    checked=$((checked + 1))
fi

# A different seed must move the values, or the seed is decoration.
"$PY" "$GEN" --seed 8 --pcap "$WORK/c.pcap" >/dev/null 2>&1
if cmp -s "$WORK/a.pcap" "$WORK/c.pcap"; then
    printf 'MISMATCH\tdeterminism\tseed 8 produced the seed %s corpus\n' "$SEED"; fail=$((fail + 1))
else
    checked=$((checked + 1))
fi

if (( fail > 0 )); then
    printf 'RESULT\tFAIL\t%d checks, %d mismatched\n' "$checked" "$fail"
    exit 1
fi
printf 'ASSERTION\tgtp-corpus-expectations\tPASS\t%d spec-pointed checks over %s cases\n' \
    "$checked" "$(awk 'NR>1' "$WORK/plan.tsv" | wc -l | tr -d ' ')"
printf 'RESULT\tPASS\n'
exit 0
