#!/usr/bin/env bash
#
# Assert the LTE RRC/SIB codec (tools/lte_asn1.py) against real captured bytes
# in tools/lte-corpus/.
#
# This check is offline by default: the corpus in tools/lte-corpus/pdus/ is
# vendored, so no network is needed. Pass --upstream to additionally re-fetch
# the two upstream captures, verify their sha256, re-extract the PDUs and
# require them to be byte-identical to the vendored ones.
#
# Why it exists: tools/lte_asn1.py is proven against pycrate 0.8.1, which
# implements TS 36.331 from the same document. If both misread a clause, every
# pycrate check still passes. The bytes here were captured from real hardware
# on a real network and were never produced by an encoder, and the expected
# values were read from Wireshark's independent lte-rrc dissector of the same
# captures -- so they test something pycrate cannot.
#
# What it covers: SIB1 (three captures, two of them a real commercial SFR
# France network) and one SystemInformation container carrying a captured SIB2
# and SIB3. Every field is asserted for its exact captured value AND for
# plausibility (assigned MCC range, non-zero TAC and cell identity, defined
# band, TS 36.331 q-RxLevMin range, valid si-WindowLength and si-Periodicity
# values, no duplicate or unknown scheduled SIB, bit counts consistent with the
# capture length). Negative controls require the codec to refuse a
# SystemInformation container at the SIB1 entry point and to keep failing on
# the real release form of SIB2's soundingRS-UL-ConfigCommon. Mutation controls
# flip one bit in six different bytes and require the decoded value to change.
#
# What it does NOT cover, stated rather than papered over: our codec cannot
# decode the captured SIB2/SIB3 bodies (SIB2: soundingRS-UL-ConfigCommon
# release form; SIB3: only the absent forms of s-NonIntraSearch /
# s-IntraSearch / p-Max are modelled), so SIB4..SIB13 are NOT asserted against
# any real capture and the SIB2/SIB3 bodies are only covered by the negative
# control. Both captures are FDD, Release-8/9 era: no TDD, no NB-IoT, no
# Rel-13+ content, no carrier aggregation. Only one of the two sources is a
# commercial network. And Wireshark implements the same unaligned-PER rules as
# pycrate, so a misreading shared by all three implementations would still be
# invisible -- see tools/lte-corpus/README.md for the full gap list.
#
# Licensing: the two upstream captures are copyleft (QCSuper GPL-3.0,
# LTESniffer AGPL-3.0) and this repository declares no licence of its own, so
# no pcap is vendored. Only the small factual PDU extracts in
# tools/lte-corpus/pdus/ are stored, with provenance. With --upstream the pcap
# files are fetched into a temporary directory OUTSIDE this repository and
# never committed.
#
# Usage:  ./tools/check-lte-corpus.sh [workdir] [--upstream]
# Exit:   0 every corpus assertion holds, 1 an assertion failed,
#         2 could not set up (missing corpus, missing codec, unfetchable or
#         wrong upstream capture). A failure is never a skip.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/tools/lte-corpus"
WORK="${TMPDIR:-/tmp}/imsisting-lte-corpus"
UPSTREAM=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --upstream) UPSTREAM=1 ;;
        -h|--help)
            sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --*)
            echo "unknown option: $1" >&2
            echo "usage: $0 [workdir] [--upstream]" >&2
            exit 2
            ;;
        *) WORK="$1" ;;
    esac
    shift
done

# Guard: the fetched copyleft capture files must never land in the repository.
case "$(cd "$(dirname "$WORK")" && pwd)/$(basename "$WORK")" in
    "$ROOT"/*)
        echo "refusing to fetch copyleft capture files into the repository: $WORK" >&2
        exit 2
        ;;
esac

[ -f "$ROOT/tools/lte_asn1.py" ] || { echo "codec not found: $ROOT/tools/lte_asn1.py" >&2; exit 2; }
[ -f "$CORPUS/vectors.json" ] || { echo "corpus manifest not found: $CORPUS/vectors.json" >&2; exit 2; }
[ -f "$CORPUS/check_corpus.py" ] || { echo "corpus checker not found: $CORPUS/check_corpus.py" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 2; }

sha256_file() {
    python3 -c 'import hashlib, sys; sys.stdout.write(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}

# --- fetch (only with --upstream) -----------------------------------------
if [ "$UPSTREAM" -eq 1 ]; then
    command -v curl >/dev/null || { echo "curl not found" >&2; exit 2; }
    echo "== fetching upstream captures (QCSuper GPL-3.0, LTESniffer AGPL-3.0) into $WORK"
    mkdir -p "$WORK"
    while IFS=$'\t' read -r name url sha; do
        [ -n "$name" ] || continue
        dest="$WORK/$name"
        if [ -s "$dest" ]; then
            have="$(sha256_file "$dest")"
            if [ "$have" = "$sha" ]; then
                echo "   cached $name ($have)"
                continue
            fi
            echo "   cached $name has sha256 $have, expected $sha -- re-fetching" >&2
        fi
        curl -fsSL -o "$dest" "$url" || { echo "could not fetch $url" >&2; exit 2; }
        have="$(sha256_file "$dest")"
        if [ "$have" != "$sha" ]; then
            echo "sha256 mismatch for $url" >&2
            echo "   got      $have" >&2
            echo "   expected $sha" >&2
            exit 2
        fi
        echo "   fetched $name ($have)"
    done < <(python3 "$CORPUS/check_corpus.py" --list-upstream)
fi

# --- assert ---------------------------------------------------------------
echo "== asserting tools/lte_asn1.py against the captured corpus"
rc=0
if [ "$UPSTREAM" -eq 1 ]; then
    python3 "$CORPUS/check_corpus.py" --root "$ROOT" --corpus "$CORPUS" \
        --upstream-dir "$WORK" || rc=$?
else
    python3 "$CORPUS/check_corpus.py" --root "$ROOT" --corpus "$CORPUS" || rc=$?
fi

if [ "$rc" -eq 0 ]; then
    echo "== the real captured LTE RRC bytes decode to the values Wireshark"
    echo "   reports for the same captures (see the coverage block above for gaps)"
else
    echo "== FAILED (exit $rc): the decoded values do not match the captures" >&2
fi
exit "$rc"
