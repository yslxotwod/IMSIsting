#!/usr/bin/env bash
# fetch-reference-data — download and normalise the public reference tables
#
# Everything this writes lands under data/public/ as TSV with a header row, so
# modules can `awk -F'\t'` over it and tools/lib/refdata.sh can look rows up.
# The output is reproducible from the sources named per table; nothing here is
# committed (see .gitignore), so a fresh checkout runs this once.
#
# Usage:
#   tools/fetch-reference-data.sh              # all tables that are reachable
#   tools/fetch-reference-data.sh --only plmn  # one table
#   tools/fetch-reference-data.sh --check      # report without downloading
#
# Exit codes follow the project contract: 0 every requested table landed,
# 1 some table could not be fetched (with the reason printed), 2 usage error.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/data/public"
CACHE="${TMP_DIR:-/tmp/imsisting}/refdata-cache"
mkdir -p "$OUT" "$CACHE" 2>/dev/null

ONLY=""
CHECK=0
while (( $# )); do
    case "$1" in
        --only)  ONLY="${2:-}"; shift 2 ;;
        --check) CHECK=1; shift ;;
        -h|--help)
            printf 'usage: fetch-reference-data.sh [--only plmn|ispc|pen] [--check]\n'
            printf '  plmn   MCC/MNC/operator register (2 500+ networks, 230 MCCs)\n'
            printf '  ispc   ITU-T Q.708 international signalling point codes (ITU Operational Bulletin annex)\n'
            printf '  pen    IANA private enterprise numbers (Diameter vendor ids)\n'
            exit 0 ;;
        *) printf 'ERROR\tunknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

wanted() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }
failures=0
note() { printf '%s\n' "$*"; }

# ── plmn ────────────────────────────────────────────────────────────────
# Source: musalbas/mcc-mnc-table, the full public MCC/MNC register with
# country and operator name per assignment. Mirror pulled over jsDelivr so the
# fetch does not depend on raw.githubusercontent remaining unblocked.
fetch_plmn() {
    local url="https://cdn.jsdelivr.net/gh/musalbas/mcc-mnc-table@master/mcc-mnc-table.json"
    local raw="$CACHE/mcc-mnc.json" tmp="$OUT/plmn.tsv"
    if ! curl -sS -m 60 -o "$raw" "$url"; then
        note "ERROR	plmn: download failed ($url)"; return 1
    fi
    if ! python3 - "$raw" "$tmp" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src, encoding="utf-8"))
rows = sorted({(e["mcc"], e["mnc"], e["country"], e["country_code"], e["network"], e["iso"]) for e in data})
with open(dst, "w", encoding="utf-8") as f:
    f.write("mcc\tmnc\tcountry\tcountry_code\toperator\tiso\n")
    for r in rows:
        f.write("\t".join(str(x).replace("\t", " ") for x in r) + "\n")
print(f"plmn	{len(rows)} networks")
PY
    then
        note "ERROR	plmn: normalisation failed"; return 1
    fi
}

# ── ispc ────────────────────────────────────────────────────────────────
# Source: the ITU Operational Bulletin's annex "List of International
# Signalling Point Codes (ISPC)", published quarterly under Q.708. The annex
# is a paginated PDF table, so it is parsed with pdftotext -layout and rows are
# rejoined across page furniture (headers, footers, wrapped operator names).
#
# This is the only public registry of which operator owns which international
# point code. Without it the SS7 module can prove a point code is well formed
# and nothing else.
fetch_ispc() {
    local url="https://www.itu.int/dms_pub/itu-t/opb/sp/T-SP-OB.1295-2024-OAS-PDF-E.pdf"
    local pdf="$CACHE/itu-ob-1295.pdf" txt="$CACHE/itu-ob-1295.txt" tmp="$OUT/ispc.tsv"
    command -v pdftotext >/dev/null 2>&1 || { note "ERROR	ispc: pdftotext missing (poppler-utils)"; return 1; }
    if [[ ! -s "$pdf" ]]; then
        curl -sS -m 120 -o "$pdf" "$url" || { note "ERROR	ispc: download failed ($url)"; return 1; }
    fi
    pdftotext -layout "$pdf" "$txt" || { note "ERROR	ispc: pdftotext failed"; return 1; }
    if ! python3 - "$txt" "$tmp" <<'PY'
import re, sys, collections
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8", errors="replace").read()
start = text.find("List of International Signalling Point Codes (ISPC) for signalling system No. 7")
if start < 0:
    sys.exit("annex heading not found")
body = text[start:].split("\n")
SKIP = ("Country/", "Geographical Area", "ISPC", "DEC", "Unique name",
        "Annex to ITU OB", "List of International", "(According", "*")
row_re = re.compile(r"^\s*(\d-\d{3}-\d)\s+(\d{3,5})\s{2,}(.*?)$")
records, country = [], ""
for raw in body:
    line = raw.replace("\x0c", "")
    s = line.strip()
    if not s:
        continue
    if s.startswith(SKIP) or re.match(r"^–\d+–$", s) or re.match(r"^\d+$", s):
        continue
    if s.startswith("declaration"):        # footnote continuation, not a country
        continue
    m = row_re.match(line)
    if m:
        rest = re.split(r"\s{2,}", m.group(3).strip(), maxsplit=1)
        records.append([country, m.group(1), m.group(2),
                        rest[0].strip() if rest else "",
                        rest[1].strip() if len(rest) > 1 else ""])
        continue
    # A country header is the shallow-indented line; anything deeper is the
    # wrapped tail of the previous operator name.
    indent = len(line) - len(line.lstrip())
    if indent <= 2:
        country = s
    elif records:
        records[-1][4] = (records[-1][4] + " " + s).strip()
if not records:
    sys.exit("no rows parsed")
seen = set()
with open(dst, "w", encoding="utf-8") as f:
    f.write("country\tispc\tispc_dec\tpoint_name\toperator\n")
    for r in records:
        if r[1] in seen:
            continue
        seen.add(r[1])
        f.write("\t".join(x.replace("\t", " ").strip() for x in r) + "\n")
print(f"ispc	{len(seen)} point codes across {len({r[0] for r in records})} countries; {sum(1 for r in records if r[3] == chr(8230))} rows carry the ITU ellipsis placeholder")
PY
    then
        note "ERROR	ispc: parse failed"; return 1
    fi
}

# ── pen ─────────────────────────────────────────────────────────────────
# Source: IANA private enterprise numbers, the registry behind Diameter
# vendor ids and SMI enterprise codes.
fetch_pen() {
    local url="https://www.iana.org/assignments/enterprise-numbers.txt"
    local raw="$CACHE/pen.txt" tmp="$OUT/pen.tsv"
    curl -sS -m 60 -o "$raw" "$url" || { note "ERROR	pen: download failed ($url)"; return 1; }
    if ! python3 - "$raw" "$tmp" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding="utf-8", errors="replace").read().split("\n")
out, i = [], 0
while i < len(lines):
    m = re.match(r"^(\d+)\s*$", lines[i].strip())
    if m:
        num, vals, j = m.group(1), [], i + 1
        while j < len(lines) and len(vals) < 3:
            s = lines[j].strip()
            if not s or re.match(r"^(\d+)\s*$", s):
                break
            vals.append(s); j += 1
        out.append((num, vals[0] if vals else "", vals[1] if len(vals) > 1 else ""))
        i = j
        continue
    i += 1
with open(dst, "w", encoding="utf-8") as f:
    f.write("pen\torganization\tcontact\n")
    for r in out:
        f.write("\t".join(x.replace("\t", " ") for x in r) + "\n")
print(f"pen	{len(out)} enterprise numbers")
PY
    then
        note "ERROR	pen: parse failed"; return 1
    fi
}

if (( CHECK )); then
    for t in plmn ispc pen; do
        if [[ -f "$OUT/$t.tsv" ]]; then
            note "$(printf 'present\t%s\t%s rows' "$t" "$(($(wc -l < "$OUT/$t.tsv") - 1))")"
        else
            note "silent	$t	not downloaded"
        fi
    done
    exit 0
fi

wanted plmn && { fetch_plmn || failures=$((failures + 1)); }
wanted ispc && { fetch_ispc || failures=$((failures + 1)); }
wanted pen  && { fetch_pen  || failures=$((failures + 1)); }

if (( failures )); then
    note "RESULT FAIL	$failures table(s) did not land"
    exit 1
fi
note "RESULT PASS	reference data under $OUT"
exit 0
