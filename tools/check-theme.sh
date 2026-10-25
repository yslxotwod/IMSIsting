#!/usr/bin/env bash
# check-theme.sh — the theme files are in step with the base sheet, and the
# binary actually carries them.
#
# The failure this exists for is not hypothetical: theme-ember.css was written,
# the Settings dropdown offered it, and choosing it changed nothing at all,
# because imsisting.gresource.xml was generated before the file existed and the
# loader found nothing. GTK does not complain about a stylesheet that is not
# there — it draws the base sheet and leaves the control reading "Ember", which
# is a lie about what is on screen. Three things are checked instead:
#
#   1. every theme-*.css on disk is named in the GResource manifest,
#   2. the generated sheet is what tools/gen-theme.py produces right now,
#   3. the manifest itself matches what tools/gen-icons-xml.sh produces.
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

for t in "${themes[@]}"; do
    [ -f "$t" ] || continue
    name=$(basename "$t")
    if ! grep -q "<file>$name</file>" "$MANIFEST"; then
        printf 'BROKEN %s is not in %s — run tools/gen-icons-xml.sh and rebuild\n' \
               "$name" "$(basename "$MANIFEST")" >&2
        bad=1
    else
        printf 'ok     %s is packaged\n' "$name"
    fi
    # A sheet the parser rejects draws nothing, and GTK says so only on stderr.
    if ! python3 - "$t" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
if text.count("{") != text.count("}"):
    sys.exit(1)
PY
    then
        printf 'BROKEN %s has unbalanced braces\n' "$name" >&2
        bad=1
    fi
done

if ! python3 "$ROOT/tools/gen-theme.py" --check >/dev/null 2>&1; then
    printf 'BROKEN a generated theme is stale — run tools/gen-theme.py\n' >&2
    bad=1
else
    printf 'ok     generated themes are up to date\n'
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
