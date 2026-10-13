#!/usr/bin/env bash
# gen-banner.sh — bake an image into the CLI banner at terminal-art fidelity.
#
# The realistic splash look (the way a modern CLI shows a mascot) comes from
# converting an actual image, not from hand-drawing characters. This wraps
# tools/img2ansi.py and writes assets/banner.ans, which imsisting.sh prefers
# over its built-in fallback art when the file exists.
#
# Usage: tools/gen-banner.sh <image> [width] [half|ascii|line]
#   half   truecolor half-blocks — photos, sprites, any image
#   line   edge-detected wireframe, tinted — a photo becomes line art
#          (this is the mode the shipped assets/banner.ans was baked with)
#   ascii  tinted luminance ramp — flat line art on a dark background
#
# Examples:
#   tools/gen-banner.sh native/resources/imsisting.png 46 line
#   tools/gen-banner.sh assets/field-kit.png 40 half
#
# Remove assets/banner.ans to go back to the built-in art.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG="${1:-}"
WIDTH="${2:-64}"
MODE="${3:-line}"

if [[ -z "$IMG" || ! -f "$IMG" ]]; then
    printf 'usage: %s <image> [width] [half|ascii]\n' "$(basename "$0")" >&2
    exit 2
fi
command -v python3 >/dev/null 2>&1 || { printf 'gen-banner: python3 required\n' >&2; exit 3; }
python3 -c 'import PIL' 2>/dev/null || { printf 'gen-banner: Pillow required (pip install Pillow)\n' >&2; exit 3; }

mkdir -p "$ROOT/assets"
OUT="$ROOT/assets/banner.ans"

case "$MODE" in
    half)
        python3 "$ROOT/tools/img2ansi.py" "$IMG" --width "$WIDTH" --mode half > "$OUT" || exit $?
        ;;
    ascii)
        # line art is bright on a dark background: drop the near-black
        # background and tint the strokes.
        python3 "$ROOT/tools/img2ansi.py" "$IMG" --width "$WIDTH" --mode ascii \
            --bits ' .:-=+*#%@' --threshold 40 --tint 8a7bff > "$OUT" || exit $?
        ;;
    line)
        # edge-detect a photo into a wireframe, the look of the reference art.
        python3 "$ROOT/tools/img2ansi.py" "$IMG" --width "$WIDTH" --mode ascii \
            --edges --dilate 1 --threshold 30 --bits ' .:-=+*#%@' --tint 8a7bff > "$OUT" || exit $?
        ;;
    *)
        printf 'gen-banner: mode must be half, ascii or line\n' >&2; exit 2 ;;
esac

printf 'wrote %s (%s lines, %s mode)\n' "$OUT" "$(wc -l < "$OUT")" "$MODE"
printf 'imsisting.sh will use it automatically; delete it to revert to the fallback art.\n'
