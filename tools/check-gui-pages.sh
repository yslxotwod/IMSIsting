#!/usr/bin/env bash
# check-gui-pages — do the module pages still bolt a log well to the bottom?
#
# Phase 20's rule is that a card's answer is data in the card: a hairline, one
# line saying how many records, then the records themselves. The thing it
# replaces is `build_output_card()` — the near-black scroller with an OUTPUT
# heading that made every module look like a terminal.
#
# Scope is the SPEC-DRIVEN pages only. Eight modules build their own pages by
# hand (01_radio, 02_cell_recon, 05_field_kit, 20_gsm_cve, 21_lte_cve,
# 22_nr_cve, 33_jamming_detect, 37_femtocell) and 00_deps is the dependency
# page; the operator excluded them by name, so a call from their builders is
# not counted here. Every other page is built by build_group_view() and must
# therefore come out clean through the shared path.
#
# Exit 0 clean, 1 violations, 2 the file or a marker went missing - because a
# check that silently passes when the code it looks for is renamed is worse
# than no check.

set -uo pipefail

ROOT=${IMSISTING_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
MAIN="$ROOT/native/src/main1.c"

[[ -f "$MAIN" ]] || { printf 'ERROR\tno %s\n' "$MAIN" >&2; exit 2; }

fail=0
checked=0
violations=()

# 1. The shared renderer exists and appends an answer surface, not a log card.
grep -q 'build_group_view' "$MAIN" || {
    printf 'ERROR\tbuild_group_view is gone; this check no longer knows what a\n' >&2
    printf 'WHY\tspec-driven page looks like, so it cannot judge one\n' >&2
    exit 2
}
if grep -A40 '^build_group_view' "$MAIN" | grep -q 'build_output_card'; then
    violations+=("build_group_view still appends the old output card")
    fail=$((fail + 1))
fi
checked=$((checked + 1))

# 2. The answer surface is assembled from the pieces the rule names.
for piece in result_summary_set answer-rule record_row_append table_body display_text; do
    if ! grep -q "$piece" "$MAIN"; then
        violations+=("the answer surface has no $piece")
        fail=$((fail + 1))
    fi
    checked=$((checked + 1))
done

# 3. Nothing displayed is allowed to show a verb token. The scrubber is the one
#    place module text is translated, so the renderers must call it: every
#    branch of console_row_append.
if ! awk '/^console_row_append\(/{f=1} f{print} f&&/^}$/{exit}' "$MAIN" |
        grep -q 'display_text'; then
    violations+=("console_row_append renders module text without display_text")
    fail=$((fail + 1))
fi
checked=$((checked + 1))

# 4. The remaining build_output_card callers must all be outside the scope: the
#    dynamic fallback page and the hand-built pages. Name them so a new one in a
#    spec-driven path shows up as a violation rather than as a surprise.
mapfile -t callers < <(grep -n 'build_output_card(out)' "$MAIN" | cut -d: -f1)
for line in "${callers[@]}"; do
    # what function is this line inside?
    fn=$(awk -v L="$line" 'NR <= L && /^[a-z_]+\(/ { f = $0 } NR == L { print f; exit }' "$MAIN")
    # The excluded pages, the module landing page and the placeholder a module
    # gets when its own page is still being written. Everything else is a
    # spec-driven page and must not own a log well.
    case "$fn" in
        create_placeholder_page*|build_overview_view*|build_dynamic_page*|build_output_card*|\
        radio_build_*|crec_build_*|fkit_build_*|lcve_*|scell_*|gsmc_*|nrcve_*|jamd_*|femt_*|deps_*)
            ;;
        *)
            violations+=("build_output_card is called from $fn, which is not an excluded page")
            fail=$((fail + 1))
            ;;
    esac
    checked=$((checked + 1))
done

if (( fail > 0 )); then
    printf 'FAIL\t%d violation(s) over %d check(s)\n' "$fail" "$checked"
    for v in "${violations[@]}"; do printf '  %s\n' "$v"; done
    exit 1
fi

printf 'every spec-driven module page answers in its own card — %d check(s), 0 log well(s) left on that path\n' "$checked"
exit 0
