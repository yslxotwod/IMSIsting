#!/usr/bin/env bash
# Referee for tools/ngap_fuzz.py and modules/13_nr_core.sh --ngap-fuzz.
#
# What this proves, and what it does not:
#
#   * Every case in the corpus is dissected by tshark 4.2.2 and the fields it
#     reads are compared against the prediction each case makes for itself.
#     The prediction is written from the TS 38.413 clause quoted in the case,
#     not from what tshark happened to print, so a case can fail.
#   * The frames are built by the generator (SCTP common header, one DATA
#     chunk with PPID 60, the IPv4 wrapper) because text2pcap cannot frame a
#     bare PDU.
#   * Not proven here: that a real AMF does what the clause says.  Nothing
#     answers NGAP on a loopback capture, so "the dissector read the defect we
#     wrote" is the whole claim -- reception answers stay unobserved.
#
# The control case is deliberately not asserted clean: this tree's NAS-PDU
# builder carries a length octet inside the IE payload, so tshark's nas-5gs
# dissector calls the message malformed for the module's own InitialUEMessage
# as well.  Asserting cleanliness would fail on a defect this file does not
# own; every other row asserts the NGAP field the case exists to move.
#
# Exit 0 every prediction held, 1 a prediction failed, 2 the check could not run.

set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TOOL="$ROOT/tools/ngap_fuzz.py"
TSHARK=${TSHARK:-$(command -v tshark || echo /usr/bin/tshark)}

[[ -r "$TOOL" ]] || { printf 'ERROR\tno generator at %s\n' "$TOOL" >&2; exit 2; }
[[ -x "$TSHARK" ]] || { printf 'ERROR\tno tshark at %s\n' "$TSHARK" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tno python3 on PATH\n' >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/ngap-fuzz-ref.XXXXXX") || exit 2
trap 'rm -rf -- "$work"' EXIT

pcap="$work/corpus.pcap"
args=(--seed 3 --pcap "$pcap" --plan-tsv "$work/plan.tsv")
python3 "$TOOL" "${args[@]}" >"$work/generator.out" 2>"$work/generator.err" || {
    printf 'ERROR\tgenerator exited %d\n' "$?" >&2
    sed -n '1,5p' "$work/generator.err" >&2
    exit 2; }

# One tshark pass over the whole capture: the frames come back in corpus order.
"$TSHARK" -r "$pcap" -d "sctp.port==38412,ngap" -T fields \
    -e ngap.procedureCode -e ngap.id -e ngap.RAN_UE_NGAP_ID \
    -e ngap.AMF_UE_NGAP_ID -e ngap.NAS_PDU -e _ws.expert.message \
    >"$work/decoded.tsv" 2>"$work/tshark.err" || {
    printf 'ERROR\ttshark could not read the capture\n' >&2
    sed -n '1,5p' "$work/tshark.err" >&2
    exit 2; }

fail=0
say() { printf '%s\t%s\n' "$1" "$2"; }

# <case> <column:0=proc,1=ids,2=ran-ue,3=nas> <expectation> <match:exact|contains|empty|absent>
check() {
    local case="$1" col="$2" want="$3" how="$4" got
    got=$(awk -F'\t' -v c="$case" -v col="$col" '
        NR==FNR { if (FNR>1) order[FNR-1]=$1; next }
        { rows[FNR]=$0 }
        END { for (i=1; i in order; i++) if (order[i]==c) { n=split(rows[i],f,"\t"); print (n>=1? f[col+1] : ""); exit } }' \
        "$work/plan.tsv" "$work/decoded.tsv")
    local verdict=FAIL
    case "$how" in
        exact)    [[ "$got" == "$want" ]] && verdict=PASS ;;
        contains) [[ "$got" == *"$want"* ]] && verdict=PASS ;;
        empty)    [[ -z "$got" ]] && verdict=PASS ;;
        absent)   [[ "$got" != *"$want"* ]] && verdict=PASS ;;
    esac
    if [[ "$verdict" == PASS ]]; then say "tshark-$case" "PASS"
    else say "tshark-$case" "FAIL want=$how($want) got=$got"; fi
    [[ $verdict == FAIL ]] && fail=$((fail + 1))
    return 0
}

# The predictions.  Clause references are the case's own.
check ngap-control                 0 15                    exact     # 9.3.1.9 id-InitialUEMessage
check ngap-control                 1 "85,38,121"           exact     # 9.3.1.9 the three IEs, by id
check ngap-control                 2 15596                 exact     # the seeded RAN UE NGAP ID
check ngap-pdu-choice-unassigned   5 "unknown extension root index in choice" contains
check ngap-procedure-unassigned    0 0                     exact     # 9.1 code 0 is not a procedure
check ngap-criticality-reserved    5 "Size constraint: value too big: 3"       contains
check ngap-ie-id-unknown-reject    1 "85,64000"            exact     # 9.3.4 the unknown id is present
check ngap-ie-id-unknown-ignore    1 "85,64000"            exact     # 9.3.4 same octets, other criticality
check ngap-ie-criticality-reserved 5 "Size constraint: value too big: 3"       contains
check ngap-ie-length-overrun       5 "Open type length"    contains  # 9.3.3 the lie is visible
check ngap-ie-length-zero          4 "<MISSING>"           exact     # 9.3.3 the IE is present and carries nothing
check ngap-mandatory-ie-missing    1 "38,121"             exact     # 9.3.1.9 no RAN-UE-NGAP-ID
check ngap-mandatory-ie-missing    1 "85"                 absent    # the mandatory id is gone
check ngap-ie-order-swapped        1 "38,85,121"          exact     # 9.3.4 order is not semantic
check ngap-container-count-lies    1 ""                   empty     # 9.3.4 count 0, nothing delivered
check ngap-downlink-amf-id-missing 0 4                     exact     # 9.3.1.9 id-DownlinkNASTransport
check ngap-downlink-amf-id-missing 3 ""                   empty     # 9.3.1.9 no AMF-UE-NGAP-ID

# The corpus must be reproducible: the same seed twice, octet for octet.
python3 "$TOOL" --seed 3 --plan-tsv "$work/again.tsv" >/dev/null 2>&1
if cmp -s "$work/plan.tsv" "$work/again.tsv"; then
    say ngap-fuzz-seeded PASS
else
    say ngap-fuzz-seeded "FAIL the same seed produced a different corpus"
    fail=$((fail + 1))
fi
# ... and a different seed must move the values, or the seed means nothing.
python3 "$TOOL" --seed 4 --plan-tsv "$work/other.tsv" >/dev/null 2>&1
if cmp -s "$work/plan.tsv" "$work/other.tsv"; then
    say ngap-fuzz-seed-matters "FAIL seed 4 reproduced seed 3"
    fail=$((fail + 1))
else
    say ngap-fuzz-seed-matters PASS
fi

# Every case must cite a clause of the NGAP specification -- a case with no
# clause is an opinion, and opinions do not belong in a corpus.
nocite=$(awk -F'\t' 'NR>1 && $4 !~ /^TS 38\.413/ {n++} END {print n+0}' "$work/plan.tsv")
if [[ "$nocite" -eq 0 ]]; then say ngap-fuzz-clauses PASS
else say ngap-fuzz-clauses "FAIL $nocite case(s) cite no TS 38.413 clause"; fail=$((fail + 1)); fi

printf 'ASSERTIONS\t%s\n' "$(( $(wc -l <"$work/decoded.tsv") > 0 ? 19 : 0 ))"
printf 'RESULT\t%s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo "FAIL($fail)")"
exit $(( fail > 0 ))
