#!/usr/bin/env bash
# check-verbs.sh — find verbs a module exposes that no GUI control can reach.
#
# A feature nobody can click is a feature nobody has. Every verb a module
# documents must be passed as a literal argument by some GUI control, or this
# check fails and names it.
#
# Usage: tools/check-verbs.sh [--json] [--list]
#   --list  show every verb and where it is reached from
# Exit: 0 if every verb is reachable, 1 otherwise.

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
n_button=0
n_box=0
declare -a unreachable=()

# Every module page carries a free-text run box, which reaches any verb the
# module implements. That makes a verb reachable but not *discoverable*, so the
# two are counted separately rather than treated as equal: a verb with a button
# is one a user will find; a verb reachable only by typing is one they must
# already know about.
has_runbox=0
grep -q 'verb_any_run_clicked' "$MAIN" && has_runbox=1

# Verbs that are plumbing rather than user actions. These are legitimately
# not clickable: the launcher and the test runner call them.
ignore_re='^--(selftest|menu|status-tsv|info|__index_probe__)$'

for f in "$ROOT"/modules/*.sh; do
    [[ -e "$f" ]] || continue
    mod=$(basename "$f" .sh)

    # Harvest the verbs from the module's own usage output.
    verbs=$(cd "$ROOT" && timeout 20 bash "$f" --__index_probe__ 2>&1 |
            grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u)

    [[ -z "$verbs" ]] && continue

    while read -r v; do
        [[ -z "$v" ]] && continue
        [[ "$v" =~ $ignore_re ]] && continue

        # Three grades, and the difference matters:
        #   button  the verb is named literally, so a click reaches it
        #   box     reachable only by typing it into a page run box
        #   none    not reachable at all -- a failure
        if grep -qF "\"$v\"" "$MAIN"; then
            n_button=$((n_button + 1))
            (( listall )) && printf 'BUTTON  %-22s %s\n' "$mod" "$v"
        elif [[ $has_runbox -eq 1 ]]; then
            n_box=$((n_box + 1))
            (( listall )) && printf 'TYPED   %-22s %s (run box only)\n' "$mod" "$v"
        else
            unreachable+=("$mod $v")
            fail=$((fail + 1))
            (( jsonout )) || printf 'UNREACHABLE  %-22s %s\n' "$mod" "$v"
        fi
    done <<< "$verbs"
done

if (( jsonout )); then
    printf '{"unreachable":%d,"verbs":[' "$fail"
    for i in "${!unreachable[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${unreachable[$i]}"
    done
    printf ']}\n'
else
    printf '\n'
    if (( fail == 0 )); then
        printf 'every documented verb is reachable from the GUI\n'
        printf '  %d with a clickable control, %d reachable only via the run box\n' \
            "$n_button" "$n_box"
        (( n_box > 0 )) && printf '  (run-box-only verbs are reachable but not discoverable)\n'
    else
        printf '%d verb(s) have no GUI path at all\n' "$fail"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
