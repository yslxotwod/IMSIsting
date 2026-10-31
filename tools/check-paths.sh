#!/usr/bin/env bash
# check-paths.sh — verify that every path the tree assumes actually resolves.
#
# The failure this catches: a module that writes to $LOOT_DIR/foo but never
# creates the directory, or a GUI table entry naming a script that does not
# exist. Both fail silently at runtime and both are cheap to catch here.
#
# Usage: tools/check-paths.sh [--json]
# Exit: 0 if every check passed, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jsonout=0
[[ "${1:-}" == "--json" ]] && jsonout=1

fail=0
declare -a problems=()

problem() {
    problems+=("$1")
    fail=$((fail + 1))
    (( jsonout )) || printf 'FAIL  %s\n' "$1"
}

(( jsonout )) || printf 'checking %s\n\n' "$ROOT"

# 1. The expected top-level tree.
#
# `wordlists` used to be required here. It is gone on purpose: nothing in the
# tree creates it (imsisting.sh:77 makes captures, logs, loot, state, tmp and
# cases, and not this), no module reads it, and git never tracked it. The only
# reason it was ever present was that somebody made the directory by hand, so
# this check failed on a clean checkout and passed on the author's box -- a
# gate whose colour came from an untracked directory. A module that needs a
# wordlist should create it the way every other runtime directory is created.
# `docs` used to be required here too. It is gone on purpose: the tree ships no
# documentation directory, and a gate that demands one would fail on a clean
# checkout of the tree it is meant to check.
for d in modules tools native native/src native/resources \
         captures logs loot state tmp bin; do
    if [[ -d "$ROOT/$d" ]]; then
        (( jsonout )) || printf 'OK    dir  %s\n' "$d"
    else
        problem "missing directory: $d"
    fi
done

# 2. The launcher and the tools.
for f in imsisting.sh stinglab.sh bin/imsisting bin/imsisting-gui bin/imsisting-tui bin/stinglab \
         tools/gen-module-index.sh tools/run-selftests.sh \
         tools/check-paths.sh tools/check-verbs.sh tools/check-gui-text.sh \
         tools/check-gsm-si.sh tools/check-manual.sh tools/check-launchers.sh; do
    if [[ -x "$ROOT/$f" ]]; then
        (( jsonout )) || printf 'OK    exec %s\n' "$f"
    elif [[ -f "$ROOT/$f" ]]; then
        problem "not executable: $f (chmod +x)"
    else
        problem "missing file: $f"
    fi
done

# 3. Every module id in the GUI table must have a script, and every script
#    must appear in the GUI table. Drift in either direction is a bug: a
#    script with no table entry is invisible, a table entry with no script
#    is a dead button.
gui_ids=$(awk '/^static const ModuleDefinition modules\[\]/,/^};/' \
            "$ROOT/native/src/main1.c" 2>/dev/null |
          grep -oE '\{ "[^"]+"' | sed 's/{ "//; s/"//')

if [[ -z "$gui_ids" ]]; then
    problem "could not parse the module table out of native/src/main1.c"
else
    for id in $gui_ids; do
        if [[ ! -f "$ROOT/modules/$id.sh" ]]; then
            problem "GUI table names $id but modules/$id.sh is missing"
        fi
    done

    for f in "$ROOT"/modules/*.sh; do
        [[ -e "$f" ]] || continue
        id=$(basename "$f" .sh)
        # A here-string, not a pipe: `printf ... | grep -q` dies of SIGPIPE
        # when grep exits at its first match, and `set -o pipefail` then
        # reports the whole pipeline as failed -- a false "missing" that
        # appears only under load. Verified: 6/6 spurious failures at a
        # payload over the pipe buffer.
        if ! grep -qx "$id" <<< "$gui_ids"; then
            problem "modules/$id.sh exists but has no entry in the GUI table"
        fi
    done
fi

# 4. Every module must be syntactically valid, or the launcher will refuse to
#    load it at runtime with a message nobody reads.
for f in "$ROOT"/modules/*.sh; do
    [[ -e "$f" ]] || continue
    if ! bash -n "$f" 2>/dev/null; then
        problem "syntax error: modules/$(basename "$f")"
    fi
done

# 4b. The launcher table must cover every module. The menu KEY is a sequential
#     position, not the module number, so the module id is carried explicitly
#     as the fifth field and checked here. A module missing from this table is
#     sourceable but unreachable from the CLI menu.
launcher_ids=$(grep -oE '^    "[A-Z0-9 /!-]+\|[0-9]{2}\|[^"|]+\|[a-z0-9_]+\|[0-9a-z_]+"' "$ROOT/imsisting.sh" 2>/dev/null |
              awk -F'|' '{gsub(/"/, "", $5); print $5}')

# Every row must carry exactly five fields. `read -r a b c d` gives the LAST
# variable the whole remainder, so a four-variable parse of a five-field row
# silently yields "fn_menu|00_mod" and the menu stops resolving. That happened
# once; this check exists so it cannot happen again.
badrows=$(grep -E '^    "[A-Z0-9 /!-]+\|' "$ROOT/imsisting.sh" 2>/dev/null |
          awk -F'|' 'NF != 5 { print NR": "$0 }')
if [[ -n "$badrows" ]]; then
    while IFS= read -r br; do
        problem "IMSISTING_MODULE_TABLE row does not have 5 fields: $br"
    done <<< "$badrows"
fi

if [[ -z "$launcher_ids" ]]; then
    problem "could not parse IMSISTING_MODULE_TABLE out of imsisting.sh"
else
    for f in "$ROOT"/modules/*.sh; do
        [[ -e "$f" ]] || continue
        id=$(basename "$f" .sh)
        if ! grep -qx "$id" <<< "$launcher_ids"; then
            problem "modules/$id.sh is missing from IMSISTING_MODULE_TABLE in imsisting.sh"
        fi
    done
    for id in $launcher_ids; do
        [[ -f "$ROOT/modules/$id.sh" ]] || \
            problem "IMSISTING_MODULE_TABLE names $id but modules/$id.sh is missing"
    done
fi

# 5. Generated artefacts must exist and be newer than nothing (freshness is
#    check-verbs/gen-module-index's job; here we only require presence).
for f in module_index.tsv native/src/module_index.c; do
    [[ -f "$ROOT/$f" ]] || problem "missing generated file: $f (run tools/gen-module-index.sh)"
done

# 6. The meson build must name a source that exists, and the gresource file
#    must exist so the CSS actually gets compiled in.
[[ -f "$ROOT/native/meson.build" ]] || problem "missing native/meson.build"
[[ -f "$ROOT/native/src/main1.c" ]] || problem "missing native/src/main1.c"
[[ -f "$ROOT/native/resources/imsisting.gresource.xml" ]] || \
    problem "missing native/resources/imsisting.gresource.xml"
[[ -f "$ROOT/native/resources/style.css" ]] || \
    problem "missing native/resources/style.css"

if (( jsonout )); then
    printf '{"fail":%d,"problems":[' "$fail"
    for i in "${!problems[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${problems[$i]//\"/\\\"}"
    done
    printf ']}\n'
else
    printf '\n'
    if (( fail == 0 )); then
        printf 'all path checks passed\n'
    else
        printf '%d problem(s)\n' "$fail"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
