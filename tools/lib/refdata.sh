#!/usr/bin/env bash
# refdata — lookup helpers over the downloaded and user-supplied reference data
#
# Sourced, never executed. Two directories, one contract:
#
#   $REFDATA_PUBLIC  data/public/   downloaded by tools/fetch-reference-data.sh
#   $REFDATA_OPOPS   data/opops/    operator-internal tables a user supplies
#
# The distinction is the doctrine in AGENTS.md §3 rule 1, applied to external
# data: a public registry entry is a fact somebody published for the world, an
# opops entry is a fact an operator kept for itself, and a missing row is
# neither. Lookups return one of three states and callers must print which:
#
#   ok           the row was found; the answer is measured
#   absent       the table was read and holds no such row
#   silent       the table is not on this machine; the answer is unobserved
#
# Callers must never collapse `silent` into `absent`. "No such operator" and
# "nobody downloaded the operator table" are different answers, and the whole
# point of the toolkit is telling them apart.

# ── paths ───────────────────────────────────────────────────────────────
# The default root is derived from this file, not from $PWD: a module may be
# run from anywhere and from a pkexec context with no launcher environment.
_refdata_self="${BASH_SOURCE[0]}"
while [ -L "$_refdata_self" ]; do
    _refdata_dir="$(cd -P "$(dirname "$_refdata_self")" && pwd)"
    _refdata_tgt="$(readlink "$_refdata_self")"
    [[ "$_refdata_tgt" != /* ]] && _refdata_tgt="$_refdata_dir/$_refdata_tgt"
    _refdata_self="$_refdata_tgt"
done
REFDATA_ROOT="${REFDATA_ROOT:-$(cd -P "$(dirname "$_refdata_self")/../.." && pwd)}"
REFDATA_PUBLIC="${REFDATA_PUBLIC:-$REFDATA_ROOT/data/public}"
REFDATA_OPOPS="${REFDATA_OPOPS:-$REFDATA_ROOT/data/opops}"

# ── state constants ─────────────────────────────────────────────────────
REFDATA_OK="ok"
REFDATA_ABSENT="absent"
REFDATA_SILENT="silent"

# ── low-level ───────────────────────────────────────────────────────────
# Column index of a header field, 1-based, 0 when the header lacks it.
# The field separator is a literal tab passed as -v: mawk does not
# interpret \t in -F the same way gawk does.
refdata_col() {  # <file> <field>
    local file="$1" field="$2"
    [[ -f "$file" ]] || { printf '0\n'; return 1; }
    awk -F'\t' -v want="$field" '
        NR == 1 { for (i = 1; i <= NF; i++) if ($i == want) { print i; exit } print 0; exit }
    ' "$file"
}

# Exact match in one column. Prints the matching line; exit 1 when absent.
refdata_pick() {  # <file> <field> <value>
    local file="$1" field="$2" value="$3" col
    [[ -f "$file" ]] || return 2
    col=$(refdata_col "$file" "$field") || return 2
    (( col > 0 )) || return 2
    awk -F'\t' -v c="$col" -v v="$value" 'NR > 1 && $c == v { print; found = 1; exit } END { exit !found }' "$file"
}

# ── PLMN ────────────────────────────────────────────────────────────────
# refdata_plmn <mcc> <mnc>
#   prints "state<TAB>operator<TAB>country"
# The MNC is compared with and without leading zeros because both spellings
# appear in the air, in SIM records and in the register: 208-01 and 208-1 are
# the same network and a caller passing either must get the same answer.
refdata_plmn() {
    local mcc="${1:-}" mnc="${2:-}" file="$REFDATA_PUBLIC/plmn.tsv" out
    if [[ -z "$mcc" || -z "$mnc" ]]; then
        printf '%s\t\t\n' "$REFDATA_SILENT"; return 0
    fi
    if [[ ! -f "$file" ]]; then
        printf '%s\t\t\n' "$REFDATA_SILENT"; return 0
    fi
    out=$(awk -F'\t' -v mcc="$mcc" -v mnc="$mnc" -v mnc2="$((10#$mnc))" '
        NR == 1 { for (i = 1; i <= NF; i++) c[i] = $i; next }
        $1 == mcc && ($2 == mnc || $2 == mnc2) { print $5 "\t" $3; found = 1; exit }
        END { exit !found }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then
        printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else
        printf '%s\t\t\n' "$REFDATA_ABSENT"
    fi
}

# ── ISPC (ITU-T Q.708 international signalling point codes) ─────────────
# refdata_ispc <4-024-0 | 12356>
#   prints "state<TAB>country<TAB>dec<TAB>point_name<TAB>operator"
# This is the table the SS7 module has never had: it turns "this point code is
# syntactically valid" into "this point code belongs to somebody, and here is
# who". A well-formed code with state=absent is the finding.
refdata_ispc() {
    local q="${1:-}" file="$REFDATA_PUBLIC/ispc.tsv" out
    if [[ ! -f "$file" ]]; then
        printf '%s\t\t\t\t\n' "$REFDATA_SILENT"; return 0
    fi
    if [[ -z "$q" ]]; then
        printf '%s\t\t\t\t\n' "$REFDATA_SILENT"; return 0
    fi
    out=$(awk -F'\t' -v q="$q" '
        NR > 1 && ($2 == q || $3 == q) { print $1 "\t" $3 "\t" $4 "\t" $5; found = 1; exit }
        END { exit !found }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then
        printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else
        printf '%s\t\t\t\t\n' "$REFDATA_ABSENT"
    fi
}

# SANC derived from an ISPC: ITU-T Q.708 fixes the first nine bits as the
# signalling area/network code, so "4-024-0" is SANC 4-024 and any point code
# in that SANC serves the same area. Pure arithmetic, no table needed.
refdata_ispc_sanc() {  # <n-mmm-d>
    local q="${1:-}"
    [[ "$q" =~ ^([0-9])-([0-9]{3})-([0-9])$ ]] || return 1
    printf '%s-%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# ── PEN (IANA private enterprise numbers) ───────────────────────────────
# refdata_pen <number>  ->  "state<TAB>organization"
# Diameter AVPs whose vendor-id is a PEN: the core module currently prints the
# bare number, which is the same answer as not knowing.
refdata_pen() {
    local q="${1:-}" file="$REFDATA_PUBLIC/pen.tsv" out
    [[ -f "$file" ]] || { printf '%s\t\n' "$REFDATA_SILENT"; return 0; }
    out=$(awk -F'\t' -v q="$q" 'NR > 1 && $1 == q { print $2; found = 1; exit } END { exit !found }' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else printf '%s\t\n' "$REFDATA_ABSENT"; fi
}

# ── operator-internal tables (data/opops) ───────────────────────────────
# Same three-state contract against the private half. A caller printing
# `gt_owner=absent` from this table is claiming the target's own published
# internals do not list the code; `gt_owner=silent` claims only that nobody
# supplied the file.
refdata_opops_gt() {  # <global title digits>
    local q="${1:-}" file="$REFDATA_OPOPS/gt.tsv" out
    [[ -f "$file" ]] || { printf '%s\t\t\n' "$REFDATA_SILENT"; return 0; }
    out=$(awk -F'\t' -v q="$q" '
        NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
        q ~ "^" $c["gt_prefix"] { print $c["plmn"] "\t" $c["stp_type"]; found = 1; exit }
        END { exit !found }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else printf '%s\t\t\n' "$REFDATA_ABSENT"; fi
}

# refdata_opops_cellblock <mcc-mnc> <cell_id>
#   -> "state<TAB>in_range<TAB>range"
# An eNB/ gNB id whose high bits fall outside the block its operator was
# allocated is a spoof or a small cell announcing somebody else's identity.
refdata_opops_cellblock() {
    local plmn="${1:-}" cid="${2:-}" file="$REFDATA_OPOPS/cellblock.tsv" out
    [[ -f "$file" ]] || { printf '%s\t\t\n' "$REFDATA_SILENT"; return 0; }
    [[ "$cid" =~ ^[0-9]+$ ]] || { printf 'error\t\t\n'; return 2; }
    out=$(awk -F'\t' -v plmn="$plmn" -v cid="$cid" '
        NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
        $c["plmn"] == plmn {
            lo = $c["range_lo"] + 0; hi = $c["range_hi"] + 0
            if (cid >= lo && cid <= hi) { print "in_block\t" lo "-" hi; found = 1; exit }
            seen = 1
        }
        END { if (!found && seen) print "out_of_block\t"; else if (!found) exit 1 }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else printf '%s\t\t\n' "$REFDATA_ABSENT"; fi
}

# refdata_opops_iprange <ip>
#   -> "state<TAB>plmn<TAB>role<TAB>cidr"
# Which core function owns an address. This is what turns a source address on
# an interconnect into a statement about a peer instead of a routing fact.
refdata_opops_iprange() {
    local ip="${1:-}" file="$REFDATA_OPOPS/iprange.tsv" out
    [[ -f "$file" ]] || { printf '%s\t\t\t\n' "$REFDATA_SILENT"; return 0; }
    out=$(awk -F'\t' -v ip="$ip" '
        function toint(s,   o, i, n) {
            n = split(s, o, ".")
            if (n != 4) return -1
            return ((o[1] + 0) * 16777216) + ((o[2] + 0) * 65536) + ((o[3] + 0) * 256) + (o[4] + 0)
        }
        NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
        {
            split($c["cidr"], ab, "/")
            if (length(ab) != 2) next
            plen = ab[2] + 0
            if (plen < 0 || plen > 32) next
            mask = sprintf("%.0f", (plen == 0) ? 0 : 4294967296 - (2 ^ (32 - plen)))
            a = toint(ab[1]); q = toint(ip)
            if (a < 0 || q < 0) next
            # awk has no 32-bit AND; derive the network by integer division so
            # the comparison stays exact for every prefix length.
            size = 2 ^ (32 - plen)
            if (int(a / size) == int(q / size)) {
                print $c["plmn"] "\t" $c["role"] "\t" $c["cidr"]; found = 1; exit
            }
        }
        END { exit !found }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else printf '%s\t\t\t\n' "$REFDATA_ABSENT"; fi
}

# refdata_opops_smsc <plmn>
#   -> "state<TAB>smsc_gt"
# The SMSC a home network routes short messages through. An SMSC identity is
# core-internal: no public registry carries it, which is why it is the only
# thing that validates an OTA command delivered to a SIM.
refdata_opops_smsc() {
    local plmn="${1:-}" file="$REFDATA_OPOPS/smsc.tsv" out
    [[ -f "$file" ]] || { printf '%s\t\n' "$REFDATA_SILENT"; return 0; }
    out=$(awk -F'\t' -v plmn="$plmn" '
        NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
        $c["plmn"] == plmn { print $c["smsc_gt"]; found = 1; exit }
        END { exit !found }
    ' "$file" 2>/dev/null)
    if [[ -n "$out" ]]; then printf '%s\t%s\n' "$REFDATA_OK" "$out"
    else printf '%s\t\n' "$REFDATA_ABSENT"; fi
}

# ── presence ────────────────────────────────────────────────────────────
# One line a caller can print when it wants to say what it could and could
# not read. `silent` rows are the honest answer, not an error.
refdata_status_line() {
    local f n
    for f in plmn.tsv ispc.tsv pen.tsv; do
        if [[ -f "$REFDATA_PUBLIC/$f" ]]; then
            n=$(($(wc -l < "$REFDATA_PUBLIC/$f") - 1))
            printf 'public/%s\tpresent\t%d rows\n' "$f" "$n"
        else
            printf 'public/%s\tsilent\tnot downloaded\n' "$f"
        fi
    done
    for f in gt.tsv cellblock.tsv iprange.tsv smsc.tsv; do
        if [[ -f "$REFDATA_OPOPS/$f" ]]; then
            n=$(($(wc -l < "$REFDATA_OPOPS/$f") - 1))
            printf 'opops/%s\tpresent\t%d rows\n' "$f" "$n"
        else
            printf 'opops/%s\tsilent\tnot supplied\n' "$f"
        fi
    done
}
