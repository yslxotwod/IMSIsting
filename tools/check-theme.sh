#!/usr/bin/env bash
# check-theme.sh — every stylesheet the GUI loads by name is in step, and the
# binary actually carries it.
#
# The failure this exists for is not hypothetical: theme-ember.css was written,
# the Settings dropdown offered it, and choosing it changed nothing at all,
# because imsisting.gresource.xml was generated before the file existed and the
# loader found nothing. GTK does not complain about a stylesheet that is not
# there — it draws the base sheet and leaves the control reading "Ember", which
# is a lie about what is on screen. The square-corner sheet is loaded the same
# way and fails the same way, so it is checked the same way. Four things:
#
#   1. every theme-*.css on disk is named in the GResource manifest,
#   2. corners.css — not a theme (it restates shape, not colour) — likewise,
#   3. the generated sheets are what tools/gen-theme.py produces right now,
#   4. the manifest itself matches what tools/gen-icons-xml.sh produces.
#
# Usage: tools/check-theme.sh            exit 0 clean, 1 broken
#        tools/check-theme.sh --list     one line per theme
set -uo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/native/resources/imsisting.gresource.xml"
bad=0

themes=( "$ROOT"/native/resources/theme-*.css )

if [ "${1:-}" = "--list" ]; then
    for t in "${themes[@]}"; do
        [ -f "$t" ] || continue
        printf '%s\n' "$(basename "$t")"
    done
    exit 0
fi

# One sheet: in the manifest, and parseable. A sheet the parser rejects draws
# nothing, and GTK says so only on stderr.
check_sheet() {
    local path="$1" name
    name=$(basename "$path")
    if ! grep -q "<file>$name</file>" "$MANIFEST"; then
        printf 'BROKEN %s is not in %s — run tools/gen-icons-xml.sh and rebuild\n' \
               "$name" "$(basename "$MANIFEST")" >&2
        bad=1
    else
        printf 'ok     %s is packaged\n' "$name"
    fi
    python3 - "$path" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
if text.count("{") != text.count("}"):
    sys.exit(1)
# GTK CSS has no !important. The parser stops at it ("Junk at end of value for
# border-radius"), drops the declaration, and the sheet draws nothing -- the
# quietest way for a sheet to be wrong.
if re.search(r"!\s*important", text):
    sys.exit(2)
PY
    local rc=$?
    if [ "$rc" != 0 ]; then
        if [ "$rc" = 2 ]; then
            printf 'BROKEN %s uses !important, which GTK CSS does not parse\n' "$name" >&2
        else
            printf 'BROKEN %s has unbalanced braces\n' "$name" >&2
        fi
        bad=1
    fi
}

for t in "${themes[@]}"; do
    [ -f "$t" ] || continue
    check_sheet "$t"
done

# The square-corner sheet. Named rather than globbed with the themes, because a
# theme may only restate colours and this one only restates shape — but it is
# loaded by name at runtime, so it has to be in the resource or choosing it
# silently draws the rounded window it was meant to replace.
if [ -f "$ROOT/native/resources/corners.css" ]; then
    check_sheet "$ROOT/native/resources/corners.css"
else
    printf 'BROKEN native/resources/corners.css is missing — the Corners setting has nothing to load\n' >&2
    bad=1
fi

if ! python3 "$ROOT/tools/gen-theme.py" --check >/dev/null 2>&1; then
    printf 'BROKEN a generated theme is stale — run tools/gen-theme.py\n' >&2
    bad=1
else
    printf 'ok     generated themes are up to date\n'
fi

if ! python3 "$ROOT/tools/gen-corners.py" --check >/dev/null 2>&1; then
    printf 'BROKEN corners.css is stale — run tools/gen-corners.py\n' >&2
    bad=1
else
    printf 'ok     square-corner sheet is up to date\n'
fi

if ! bash "$ROOT/tools/gen-icons-xml.sh" --check >/dev/null 2>&1; then
    printf 'BROKEN the GResource manifest is stale — run tools/gen-icons-xml.sh\n' >&2
    bad=1
else
    printf 'ok     GResource manifest is up to date\n'
fi

if [ "$bad" = 0 ]; then
    printf 'check-theme: RESULT PASS\n'
else
    printf 'check-theme: RESULT FAIL\n'
fi
exit "$bad"
