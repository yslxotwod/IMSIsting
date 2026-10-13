#!/usr/bin/env bash
# run-selftests.sh — run every module's --selftest and report.
#
# This is the only test runner in the tree, so it is the only thing standing
# between a broken parser and a shipped module. A module with no --selftest is
# reported as MISSING rather than silently skipped, so the count of untested
# modules stays visible instead of quietly shrinking the denominator.
#
# Usage:
#   tools/run-selftests.sh              # every module that has one
#   tools/run-selftests.sh --all        # include modules without one (MISSING)
#   tools/run-selftests.sh 02 13        # only these numbers/prefixes
#   tools/run-selftests.sh --quiet      # only failures
#   tools/run-selftests.sh --json       # machine-readable
#
# Exit: 0 if every module that has a selftest passed, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODDIR="$ROOT/modules"
TIMEOUT="${SELFTEST_TIMEOUT:-120}"

show_all=0 quiet=0 jsonout=0
filters=()
for arg in "$@"; do
    case "$arg" in
        --all)   show_all=1 ;;
        --quiet) quiet=1 ;;
        --json)  jsonout=1 ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) filters+=("$arg") ;;
    esac
done

command -v timeout >/dev/null 2>&1 || { echo "timeout not found" >&2; exit 2; }

pass=0 fail=0 missing=0
declare -a failed=() missing_list=()

mapfile -t modules < <(cd "$MODDIR" && ls -1 *.sh 2>/dev/null | sort)

for m in "${modules[@]}"; do
    name="${m%.sh}"

    if (( ${#filters[@]} > 0 )); then
        keep=0
        for f in "${filters[@]}"; do
            [[ "$name" == "$f" || "$name" == "$f"_* || "$name" == *"$f"* ]] && keep=1
        done
        (( keep )) || continue
    fi

    if ! grep -q -- '--selftest' "$MODDIR/$m" 2>/dev/null; then
        missing=$((missing + 1)); missing_list+=("$name")
        (( jsonout )) || { (( quiet )) || printf 'MISSING  %s\n' "$name"; }
        continue
    fi

    out=$(cd "$ROOT" && timeout "$TIMEOUT" bash "$MODDIR/$m" --selftest 2>&1)
    rc=$?

    # NB: \t is not a tab in POSIX ERE (that is a PCRE extension), so the
    # tab is matched with [[:space:]].
    if (( rc == 0 )) && grep -qE 'RESULT[[:space:]]+PASS' <<<"$out"; then
        pass=$((pass + 1))
        if (( ! quiet && ! jsonout )); then
            n=$(grep -cE '^[^[:space:]]+[[:space:]]+PASS' <<<"$out" || true)
            printf 'PASS     %-26s %s checks\n' "$name" "${n:-0}"
        fi
    else
        fail=$((fail + 1)); failed+=("$name")
        if (( ! jsonout )); then
            printf 'FAIL     %-26s rc=%s\n' "$name" "$rc"
            grep -E 'FAIL' <<<"$out" | head -6 | sed 's/^/           /'
            (( rc == 124 )) && printf '           timed out after %ss\n' "$TIMEOUT"
        fi
    fi
done

if (( jsonout )); then
    printf '{"pass":%d,"fail":%d,"missing":%d,"failed":[' "$pass" "$fail" "$missing"
    for i in "${!failed[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${failed[$i]}"
    done
    printf ']}\n'
else
    printf '\n'
    printf 'passed %d   failed %d   no selftest %d\n' "$pass" "$fail" "$missing"
    if (( show_all && ${#missing_list[@]} > 0 )); then
        printf 'untested: %s\n' "${missing_list[*]}"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
