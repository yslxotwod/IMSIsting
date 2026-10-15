#!/usr/bin/env bash
# check-verbs.sh — find verbs a module exposes that no GUI control can reach.
#
# A feature nobody can click is a feature nobody has. Every verb a module
# documents must either sit in one of its submenu groups (so it is clickable),
# or be a plumbing verb that belongs to the launcher and the test runner rather
# than to a person. A verb in neither category is a failure, and this check
# names it.
#
# Placement is read from the group specs in native/src/main1.c, where each
# module lists its submenus as "verb[!][@][:Label]" entries.
#
# Usage: tools/check-verbs.sh [--json] [--list]
#   --list  show every verb and where it is reached from
# Exit: 0 if every verb is placed or exempt, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN="$ROOT/native/src/main1.c"
jsonout=0
listall=0
for a in "$@"; do
    case "$a" in
        --json) jsonout=1 ;;
        --list) listall=1 ;;
    esac
done

[[ -f "$MAIN" ]] || { echo "no $MAIN" >&2; exit 2; }

fail=0
n_placed=0
n_exempt=0
n_cli=0
declare -a unreachable=()

# Plumbing and modifier verbs. These are not user actions: the launcher, the
# test runner and the module internals call them. They are allowed to have no
# button.
exempt_re='^--(menu|selftest|status-tsv|info|__index_probe__|yes|quiet|help|version)$'

# main1.c with every submenu table stripped out. A verb found in here is wired
# from C code -- a custom view building its own controls -- rather than named in
# a spec string. Keeping the two apart is what stops one module borrowing
# another's spec line.
codeonly=$(awk '/^static ModuleSubmenuEntry [a-z0-9_]+_entries\[\] = \{/ { f=1 }
                f && /^\};/ { f=0; next }
                !f' "$MAIN")

for f in "$ROOT"/modules/*.sh; do
    [[ -e "$f" ]] || continue
    mod=$(basename "$f" .sh)

    # Harvest the verbs from the module's own usage output.
    verbs=$(cd "$ROOT" && timeout 20 bash "$f" --__index_probe__ 2>&1 |
            grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u)

    [[ -z "$verbs" ]] && continue

    # Scope every lookup to THIS module's own submenu table. Matching the bare
    # verb name anywhere in main1.c lets a verb borrow another module's entry:
    # 13_lte_attach's --identity-exposure was reported PLACED on the strength of
    # 10_gsm_air's spec, which hid that it had no working control at all.
    tab=$(grep -oE "module_registry_register\(\"$mod\", *[a-z0-9_]+_entries" "$MAIN" |
          head -1 | grep -oE '[a-z0-9_]+_entries')
    spec=""
    if [[ -n "$tab" ]]; then
        spec=$(awk "/static ModuleSubmenuEntry ${tab}\\[\\] = \\{/{f=1} f{print} f&&/^};/{exit}" "$MAIN")
    fi
    [[ -n "$spec" ]] || spec="$MAIN"

    while read -r v; do
        [[ -z "$v" ]] && continue

        if [[ "$v" =~ $exempt_re ]]; then
            n_exempt=$((n_exempt + 1))
            (( listall )) && printf 'EXEMPT   %-22s %s\n' "$mod" "$v"
            continue
        fi

        # A '~' prefix in a group spec marks a verb that needs an argument only
        # the operator knows: it is deliberately kept on the command line.
        if grep -qE -- "~${v}([^a-z0-9-]|\$)" <<< "$spec"; then
            n_cli=$((n_cli + 1))
            (( listall )) && printf 'CLI-ONLY %-22s %s\n' "$mod" "$v"
            continue
        fi

        # Placed means the verb is named in this module's group spec in
        # main1.c. Match it as a whole token so --list does not satisfy
        # --list-tsv. A verb the module's own C code calls is reachable too --
        # custom views build their controls directly -- so fall back to the
        # code-only view of main1.c.
        if grep -qE -- "(^|[^a-z0-9-])${v}([^a-z0-9-]|\$)" <<< "$spec" ||
           grep -qE -- "(^|[^a-z0-9-])${v}([^a-z0-9-]|\$)" <<< "$codeonly"; then
            n_placed=$((n_placed + 1))
            (( listall )) && printf 'PLACED   %-22s %s\n' "$mod" "$v"
        else
            unreachable+=("$mod $v")
            fail=$((fail + 1))
            (( jsonout )) || printf 'UNPLACED  %-22s %s\n' "$mod" "$v"
        fi
    done <<< "$verbs"
done

if (( jsonout )); then
    printf '{"unplaced":%d,"verbs":[' "$fail"
    for i in "${!unreachable[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${unreachable[$i]}"
    done
    printf ']}\n'
else
    printf '\n'
    if (( fail == 0 )); then
        printf 'every documented verb is placed in a submenu or exempt\n'
        printf '  %d placed as one-click buttons, %d CLI-only (need an argument), %d exempt plumbing verbs\n' \
            "$n_placed" "$n_cli" "$n_exempt"
    else
        printf '%d verb(s) are neither placed in a submenu nor exempt\n' "$fail"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
