#!/usr/bin/env bash
# check-placed-verbs.sh — every verb the GUI places must exist in that module.
#
# check-verbs.sh answers "can a person reach this verb?". This answers the other
# half of the same question: "does the thing they reach actually exist?". The two
# failures look identical on screen and only one of them is a feature:
#
#   a verb with no control        -> a feature nobody can click
#   a control with no verb        -> a button that prints "unknown: --foo"
#
# The second is the harder one to notice, because it is invisible until someone
# clicks it, and it appears whenever a page is written against a module that is
# being edited at the same time. tools/check-verbs.sh cannot see it: placement is
# matched against the module's OWN entries block, so a verb placed on module A's
# page but implemented only in module B passes there. That is exactly how
# 02_cell_recon --inventory once read as "placed" while 02_cell_recon had no such
# verb -- 63_ran_attacks places a verb with the same name.
#
# Usage: tools/check-placed-verbs.sh [--list]
#   --list  print every placed verb and the module it was checked against
# Exit: 0 when every placed verb is dispatched by its own module, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN="$ROOT/native/src/main1.c"
MODIFIERS="$ROOT/tools/verb-modifiers.txt"
listall=0
[[ "${1:-}" == "--list" ]] && listall=1

[[ -f "$MAIN" ]] || { echo "no $MAIN" >&2; exit 2; }

# Verbs the launcher and the test runner own, not the module. They are buttons on
# every page and no module dispatches them, so they are exempt here for the same
# reason they are exempt in tools/check-verbs.sh.
exempt_re='^(menu|selftest|status-tsv|info|__index_probe__|yes|quiet|help|version|prepare|preflight|ota-test|pci|out)$'

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# A modifier is an argument, not an action: --earfcn names a carrier for
# --tx-build. It is never dispatched as a verb, so it is never expected to be.
if [[ -f "$MODIFIERS" ]]; then
    sed 's/[[:space:]]*$//' "$MODIFIERS" | grep -vE '^#|^$' | sort -u > "$tmp/modifiers.txt"
else
    : > "$tmp/modifiers.txt"
fi

# 1. What the GUI places, per module.
#
# Two shapes carry a verb. A chip row is a tuple: { "NN_module", "--verb", NEED_x,
# DOES_x }. A spec entry lives inside that module's own *_entries[] block and
# reads "verb[!][@][=default][:Label]", joined by '|' within one string. Both are
# read here, because both become a button.
awk '
    /static ModuleSubmenuEntry [a-z0-9_]*_entries\[\] *= *\{/ {
        inside = 1
        match($0, /ModuleSubmenuEntry [a-z0-9_]*_entries/)
        ent = substr($0, RSTART, RLENGTH)
        sub(/^ModuleSubmenuEntry /, "", ent)
        sub(/_entries$/, "", ent)
        next
    }
    inside && /^\};/ { inside = 0; next }
    inside {
        # every quoted run in the block is a candidate spec
        while (match($0, /"[^"]*"/)) {
            s = substr($0, RSTART + 1, RLENGTH - 2)
            print "SPEC\t" ent "\t" s
            $0 = substr($0, RSTART + RLENGTH)
        }
        next
    }
    /^ *\{ *"[0-9][0-9]_[a-z0-9_]*", *"--[a-z0-9-]+"/ {
        line = $0
        if (match(line, /"[0-9][0-9]_[a-z0-9_]*"/)) {
            mid = substr(line, RSTART + 1, RLENGTH - 2)
            rest = substr(line, RSTART + RLENGTH)
            if (match(rest, /"--[a-z0-9-]+"/))
                print "CHIP\t" mid "\t" substr(rest, RSTART + 1, RLENGTH - 2)
        }
    }
' "$MAIN" > "$tmp/placed.tsv"

# Spec entries also appear as bare verb strings in a spec with no chip tuple, so
# the module id for a spec line has to come from the block's own name: the
# convention is <short>_entries with <short> the module"s short name, which is
# how every module in this tree is written. Resolve it against modules[].
awk -F'\t' '$1 == "SPEC" { print $2 }' "$tmp/placed.tsv" | sort -u > "$tmp/shorthands.txt"
: > "$tmp/shortmap.tsv"
while read -r sh; do
    [[ -z "$sh" ]] && continue
    # The registration call is authoritative: module_registry_register("NN_mod",
    # sh_entries, ...). Fall back to a prefix match on the module id.
    mod=$(grep -oE "module_registry_register\(\"[0-9][0-9]_[a-z0-9_]+\",[[:space:]]*${sh}_entries" "$MAIN" 2>/dev/null \
          | head -1 | sed 's/module_registry_register("//; s/".*//')
    if [[ -z "$mod" ]]; then
        mod=$(grep -oE "\{ \"[0-9][0-9]_${sh}\"" "$MAIN" 2>/dev/null | head -1 | sed 's/{ "//; s/"//')
    fi
    printf '%s\t%s\n' "$sh" "${mod:-?}" >> "$tmp/shortmap.tsv"
done < "$tmp/shorthands.txt"

# 2. What each module dispatches.
: > "$tmp/dispatch.tsv"
for f in "$ROOT"/modules/[0-9][0-9]_*.sh; do
    id=$(basename "$f" .sh)
    # A dispatcher arm is `--verb)` or `--verb|--alias)`. Anything else that
    # merely mentions the word (a usage line, a comment) is not a dispatch.
    # An arm is a case pattern at the start of a line, or chained after `;;` on
    # the same line. 42_li_probe carries four arms on one line, which is legal
    # bash and which a line-anchored match silently reports as missing; matching
    # `--verb)` anywhere instead over-matches the usage heredoc.
    grep -oE -- '(^|;;)[[:space:]]*--[a-z0-9-]+(\|--[a-z0-9-]+)*\)' "$f" 2>/dev/null \
      | sed 's/^;;[[:space:]]*//; s/^[[:space:]]*//; s/)$//' \
      | tr '|' '\n' \
      | sed 's/^--//' \
      | while read -r v; do [[ -n "$v" ]] && printf '%s\t%s\n' "$id" "$v"; done >> "$tmp/dispatch.tsv"
done

# 3. Compare.
fail=0
n_checked=0
while IFS=$'\t' read -r kind who verb; do
    case "$kind" in
        CHIP) mod="$who" ;;
        SPEC) mod=$(awk -F'\t' -v s="$who" '$1==s{print $2; exit}' "$tmp/shortmap.tsv") ;;
        *) continue ;;
    esac
    [[ -z "${mod:-}" || "$mod" == "?" ]] && continue
    # Spec strings carry labels, defaults, markers and section headers; only the
    # token that starts with -- is a verb.
    tok=$(printf '%s' "$verb" | sed 's/^[#~]//' | cut -d: -f1 | cut -d= -f1 | awk '{print $1}')
    case "$tok" in
        --*) ;;
        *) continue ;;
    esac
    name=${tok#--}
    grep -qx "$name" "$tmp/modifiers.txt" && continue
    [[ "$name" =~ $exempt_re ]] && continue
    n_checked=$(( n_checked + 1 ))
    [[ "$listall" == 1 ]] && printf '%-28s %s\n' "$mod" "$tok"
    if ! grep -qxF -e "$mod	$name" "$tmp/dispatch.tsv"; then
        printf 'MISSING  %-22s %-24s no dispatch arm in modules/%s.sh\n' "$mod" "$tok" "$mod"
        fail=$(( fail + 1 ))
    fi
done < "$tmp/placed.tsv"

if [[ $fail -eq 0 ]]; then
    echo "every placed verb is dispatched by its own module ($n_checked checked)"
    exit 0
fi
echo "$fail placed verb(s) have no dispatch arm in the module they are placed on"
exit 1
