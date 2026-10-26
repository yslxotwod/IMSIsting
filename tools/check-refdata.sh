#!/usr/bin/env bash
# check-refdata — the reference-table loader behaves as specified
#
# The loader's entire contract is the three-state answer (ok / absent /
# silent), and the failure it exists to prevent is a missing table being read
# as a negative finding. This gate builds fixture tables, points the loader at
# them, and asserts each state — so it runs on a machine that has never
# downloaded anything, and still catches a regression that collapses the
# states together.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/lib/refdata.sh
source "$ROOT/tools/lib/refdata.sh"

bad=0
asserts=0
chk() {
    local name="$1" got="$2" want="$3"
    asserts=$((asserts + 1))
    if [[ "$got" == "$want" ]]; then
        printf 'ASSERTION\t%s\tPASS\n' "$name"
    else
        printf 'ASSERTION\t%s\tFAIL\twant=%s\tgot=%s\n' "$name" "$want" "$got"
        bad=$((bad + 1))
    fi
}

d=$(mktemp -d "${TMPDIR:-/tmp}/check-refdata.XXXXXX") || exit 1
trap 'rm -rf "$d"' EXIT

mkdir -p "$d/public" "$d/opops"
printf 'mcc\tmnc\tcountry\tcountry_code\toperator\tiso\n' > "$d/public/plmn.tsv"
printf '208\t01\tFrance\t33\tOrange\tFR\n' >> "$d/public/plmn.tsv"
printf '208\t02\tFrance\t33\tOrange\tFR\n' >> "$d/public/plmn.tsv"
printf '310\t260\tUnited States\t1\tT-Mobile\tUS\n' >> "$d/public/plmn.tsv"

printf 'country\tispc\tispc_dec\tpoint_name\toperator\n' > "$d/public/ispc.tsv"
printf 'France\t2-001-0\t2056\tPARIS\tPrivate Operator SA\n' >> "$d/public/ispc.tsv"
printf 'France\t2-001-1\t2057\t…\tPrivate Operator SA\n' >> "$d/public/ispc.tsv"

printf 'pen\torganization\tcontact\n' > "$d/public/pen.tsv"
printf '10415\tHuawei Technologies\tHuawei\n' >> "$d/public/pen.tsv"

printf 'gt_prefix\tplmn\tstp_type\tnote\n' > "$d/opops/gt.tsv"
printf '470011\t470-01\tstp\tprimary\n' >> "$d/opops/gt.tsv"
printf 'plmn\trange_lo\trange_hi\tkind\tnote\n' > "$d/opops/cellblock.tsv"
printf '404-01\t100000\t199999\teNB\turban\n' >> "$d/opops/cellblock.tsv"
printf 'plmn\tcidr\trole\tnote\n' > "$d/opops/iprange.tsv"
printf '410-01\t198.51.100.0/26\tgrx-peer\tcontracted\n' >> "$d/opops/iprange.tsv"
printf '410-01\t10.0.0.0/8\tcore\town core\n' >> "$d/opops/iprange.tsv"
printf 'plmn\tsmsc_gt\tnote\n' > "$d/opops/smsc.tsv"
printf '410-01\t13104100000\thome SMSC\n' >> "$d/opops/smsc.tsv"

REFDATA_PUBLIC="$d/public"
REFDATA_OPOPS="$d/opops"

# ── PLMN ────────────────────────────────────────────────────────────────
chk plmn-ok            "$(refdata_plmn 208 01 | cut -f1,2)"  "ok	Orange"
chk plmn-unpadded-mnc  "$(refdata_plmn 208 1  | cut -f1,2)"  "ok	Orange"
chk plmn-us            "$(refdata_plmn 310 260 | cut -f2)"   "T-Mobile"
chk plmn-absent        "$(refdata_plmn 999 99  | cut -f1)"   "absent"
chk plmn-empty-args    "$(refdata_plmn '' ''    | cut -f1)"   "silent"

# ── ISPC ────────────────────────────────────────────────────────────────
chk ispc-ok            "$(refdata_ispc 2-001-0 | cut -f1,2)" "ok	France"
chk ispc-operator      "$(refdata_ispc 2-001-0 | cut -f5)"   "Private Operator SA"
chk ispc-by-decimal    "$(refdata_ispc 2056 | cut -f1)"      "ok"
chk ispc-withheld      "$(refdata_ispc 2-001-1 | cut -f4)"   "…"
chk ispc-absent        "$(refdata_ispc 9-999-7 | cut -f1)"   "absent"
chk ispc-sanc          "$(refdata_ispc_sanc 2-001-0)"        "2-001"
chk ispc-sanc-bad      "$(refdata_ispc_sanc nonsense >/dev/null 2>&1; echo $?)" "1"

# ── PEN ─────────────────────────────────────────────────────────────────
chk pen-ok             "$(refdata_pen 10415 | cut -f1,2)"    "ok	Huawei Technologies"
chk pen-absent         "$(refdata_pen 99999 | cut -f1)"      "absent"

# ── operator tables ─────────────────────────────────────────────────────
chk opops-gt-ok        "$(refdata_opops_gt 4700112345 | cut -f1,2)" "ok	470-01"
chk opops-gt-absent    "$(refdata_opops_gt 1112223333 | cut -f1)"   "absent"
chk opops-block-in     "$(refdata_opops_cellblock 404-01 150000 | cut -f2)" "in_block"
chk opops-block-out    "$(refdata_opops_cellblock 404-01 999999 | cut -f2)" "out_of_block"
chk opops-block-plmn   "$(refdata_opops_cellblock 999-99 150000 | cut -f1)" "absent"
chk opops-iprange-in   "$(refdata_opops_iprange 198.51.100.5 | cut -f1,2,3)" "ok	410-01	grx-peer"
chk opops-iprange-out  "$(refdata_opops_iprange 8.8.8.8 | cut -f1)"          "absent"
chk opops-iprange-edge "$(refdata_opops_iprange 198.51.101.0 | cut -f1)"     "absent"
chk opops-iprange-wide "$(refdata_opops_iprange 10.255.0.1 | cut -f2,3)"     "410-01	core"
chk opops-smsc-ok      "$(refdata_opops_smsc 410-01 | cut -f1,2)"            "ok	13104100000"
chk opops-smsc-absent  "$(refdata_opops_smsc 999-99 | cut -f1)"              "absent"

# ── presence ────────────────────────────────────────────────────────────
chk presence-public    "$(refdata_status_line | awk -F'\t' '$1=="public/plmn.tsv"{print $2}')" "present"
chk presence-opops     "$(refdata_status_line | awk -F'\t' '$1=="opops/gt.tsv"{print $2}')" "present"
chk presence-smsc      "$(refdata_status_line | awk -F'\t' '$1=="opops/smsc.tsv"{print $2}')" "present"
chk presence-iprange   "$(refdata_status_line | awk -F'\t' '$1=="opops/iprange.tsv"{print $2}')" "present"

# ── the states must not collapse ────────────────────────────────────────
# With no public directory at all, every public lookup reports silent — and in
# particular does NOT report absent, which would be a manufactured finding.
REFDATA_PUBLIC="$d/does-not-exist"
chk missing-plmn       "$(refdata_plmn 208 01 | cut -f1)"     "silent"
chk missing-ispc       "$(refdata_ispc 2-001-0 | cut -f1)"    "silent"
chk missing-pen        "$(refdata_pen 10415 | cut -f1)"       "silent"
chk missing-not-absent "$([[ "$(refdata_plmn 208 01 | cut -f1)" == "absent" ]]; echo $?)" "1"
REFDATA_PUBLIC="$d/public"

# ── the fetcher's contract ──────────────────────────────────────────────
chk fetch-usage        "$(bash "$ROOT/tools/fetch-reference-data.sh" --bogus >/dev/null 2>&1; echo $?)" "2"
chk fetch-help         "$(bash "$ROOT/tools/fetch-reference-data.sh" --help | grep -c "^  ispc")" "1"
chk fetch-check        "$(bash "$ROOT/tools/fetch-reference-data.sh" --check >/dev/null 2>&1; echo $?)" "0"

printf 'ASSERTIONS\t%d\n' "$asserts"
if (( bad )); then
    printf 'RESULT\tFAIL(%d)\n' "$bad"
    exit 1
fi
printf 'RESULT\tPASS\n'
