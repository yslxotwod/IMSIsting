#!/usr/bin/env python3
"""gen-theme.py — derive a theme stylesheet from the base one.

A theme here is not a second design. The base sheet (native/resources/style.css)
is written around a palette and the exact colours of the bench it was drawn for.
A derived theme restates that palette one temperature over and keeps every rule
where it was: the layout is never copied, so a theme cannot fall behind it, and a
palette that drifts upstream shows up as a diff in the generated file instead of
as one panel that stayed blue.

How a colour is re-derived (see `ember`):

  neutral (saturation under 0.25)  -> the same grey, warmed: hue to 28 degrees
                                      with a whisper of saturation. This is what
                                      turns the blue-grey text and the cool
                                      borders into warm ones without touching
                                      how light they are.
  cool (hue 175..245, mid to light) -> the accent: 22 degrees, saturated, and a
                                      little darker, so a cyan highlight lands
                                      as ember.
  cool and dark (lightness < 0.30)  -> a surface: hue to 24, most saturation
                                      dropped, and darker still, so the navy
                                      panels become near-black with a warm bias.
  cool and very light (>= 0.75)     -> a near-white, i.e. text: warmed, not
                                      tinted, because an accent-coloured label
                                      that size is unreadable.
  everything else                   -> left alone but calmed by 8 percent of
                                      saturation. Green still means ok, red still
                                      means danger: a theme that recolours the
                                      status hues makes the honest chip lie.

Dark surfaces are also given a little transparency, which is what makes the desk
read as layers over the base glow rather than as flat panels. A toplevel window
cannot be translucent without a compositing manager, so this is depth inside the
window, not a see-through window.

Usage:
  tools/gen-theme.py                 write native/resources/theme-ember.css
  tools/gen-theme.py --check         exit 1 if the file on disk is stale
  tools/gen-theme.py --map '#4fb3d9' print what one colour becomes
"""
from __future__ import annotations

import argparse
import colorsys
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_CSS = ROOT / "native/resources/style.css"
OUT_CSS = ROOT / "native/resources/theme-ember.css"

# ── the palette of the derived theme ────────────────────────────────────────
# Named colours the base sheet already defines win over the derivation, because
# a palette value is a decision and a derivation is a rule.
PALETTE = {
    "bg_base":   "#050608",
    "bg_panel":  "rgba(14, 13, 13, 0.88)",
    "bg_panel2": "rgba(11, 10, 10, 0.88)",
    "bg_sunken": "#030304",
    "line":      "#241f1c",
    "card_bg":   "rgba(18, 17, 17, 0.90)",
    "card_hi":   "rgba(26, 24, 24, 0.94)",
    "text":      "#e9e4df",
    "text_dim":  "#9c948c",
    "accent":    "#ff7a29",
}

# Surfaces get an alpha so a panel reads as a layer. Only dark colours qualify:
# a light one with alpha would wash out over black.
SURFACE_L = 0.30
SURFACE_ALPHA = 0.92

COOL_LO, COOL_HI = 175.0, 245.0


def _hsl(rgb: tuple[float, float, float]):
    return colorsys.rgb_to_hls(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0)


def _rgb(h: float, l: float, s: float) -> tuple[int, int, int]:
    r, g, b = colorsys.hls_to_rgb((h % 360.0) / 360.0,
                                  max(0.0, min(1.0, l)),
                                  max(0.0, min(1.0, s)))
    return (round(r * 255), round(g * 255), round(b * 255))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def ember(rgb: tuple[float, float, float], alpha: float = 1.0):
    """One colour, one temperature over. Returns (r, g, b, a)."""
    h, l, s = _hsl(rgb)
    hue = h * 360.0

    if s < 0.25:                                   # neutral: warm the grey
        out = _rgb(28.0, l, min(s * 0.35 + 0.03, 0.10))
    elif COOL_LO <= hue <= COOL_HI and l < SURFACE_L:   # a dark surface
        out = _rgb(24.0, l * 0.86, min(s * 0.50, 0.34))
    elif COOL_LO <= hue <= COOL_HI and l >= 0.75:  # near-white text
        out = _rgb(30.0, l * 0.99, min(s * 0.25, 0.10))
    elif COOL_LO <= hue <= COOL_HI:                # the accent family
        out = _rgb(22.0, _clamp(l * 0.98, 0.50, 0.68),
                   _clamp(max(s, 0.72), 0.0, 0.88))
    else:                                          # status hues stay themselves
        out = _rgb(hue, l, s * 0.92)

    if alpha >= 0.999 and (out[0] + out[1] + out[2]) / (3.0 * 255.0) < SURFACE_L:
        alpha = SURFACE_ALPHA
    return (out[0], out[1], out[2], alpha)


def _fmt(rgba) -> str:
    r, g, b, a = rgba
    if a >= 0.999:
        return f"#{r:02x}{g:02x}{b:02x}"
    return f"rgba({r}, {g}, {b}, {a:g})"


HEX_RE = re.compile(r"#([0-9a-fA-F]{6})(?![0-9a-fA-F])")
RGBA_RE = re.compile(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)")


def convert_value(value: str) -> str:
    """Rewrite every colour in a declaration value, leaving the rest alone."""
    def hex_sub(match):
        h = match.group(1)
        return _fmt(ember((int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))))

    def rgba_sub(match):
        r, g, b = (int(match.group(i)) for i in (1, 2, 3))
        a = float(match.group(4)) if match.group(4) else 1.0
        return _fmt(ember((r, g, b), a))

    value = HEX_RE.sub(hex_sub, value)
    return RGBA_RE.sub(rgba_sub, value)


def has_colour(value: str) -> bool:
    return bool(HEX_RE.search(value) or RGBA_RE.search(value))


DEFINE_RE = re.compile(r"@define-color\s+([a-z0-9_-]+)\s+([^;]+);", re.I)


def split_rules(css: str):
    """Yield (selector, body) for every block, with comments already stripped."""
    i, n = 0, len(css)
    depth = 0
    start = 0
    while i < n:
        ch = css[i]
        if ch == "{":
            if depth == 0:
                selector = css[start:i].strip()
                body_start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                yield selector, css[body_start:i]
                start = i + 1
        i += 1


# The base sheet paints what the toolkit draws itself and leaves GTK's own
# widgets to the system theme. In a near-black warm window that shows: an entry
# kept Adwaita's navy field, a popover kept Adwaita's grey card, and both read as
# guests from another application. These rules are the widgets the base sheet
# does not speak for, restated once, in colours only — no padding, no radius, no
# sizing, so the "a theme restates colours and nothing else" claim stays true.
CHROME = """\
/* ── widget chrome ───────────────────────────────────────────────────────
   The widgets the base sheet does not style, because until now the system
   theme's version was close enough. Against near-black and ember it is not:
   the header search kept a navy field. Colours only, so a shape that changes
   in the base sheet still arrives here. */
entry,
spinbutton,
searchentry {
  background-color: #100f0e;
  color: @text;
  border: 1px solid #2b2521;
  box-shadow: none;
  caret-color: @accent;
}

entry > text > placeholder,
searchentry > text > placeholder,
spinbutton > text > placeholder {
  color: #6d665f;
}

entry:focus-within,
spinbutton:focus-within,
searchentry:focus-within {
  border-color: #6f3a1c;
  box-shadow: 0 0 0 1px #3a2317 inset;
}

entry:disabled,
searchentry:disabled {
  background-color: #0b0a0a;
  color: #6d665f;
}

selection,
*:selected {
  background-color: rgba(255, 122, 41, 0.30);
  color: #f6f1eb;
}

popover,
popover.background,
popover > contents {
  background-color: #121110;
  color: @text;
  border: 1px solid #2b2521;
}

popover.menu > contents,
dropdown popover > contents {
  background-color: #15120f;
}

popover listview,
popover list,
dropdown popover listview {
  background-color: transparent;
}

dropdown popover listview > row,
popover.menu modelbutton,
popover.menu > contents > box > button {
  color: @text;
}

dropdown popover listview > row:hover,
popover.menu modelbutton:hover {
  background-color: rgba(255, 122, 41, 0.12);
}

dropdown popover listview > row:selected {
  background-color: rgba(255, 122, 41, 0.22);
  color: #f8f3ed;
}

tooltip,
tooltip.background {
  background-color: #1a1714;
  color: #e2dbd3;
  border: 1px solid #33291f;
}

checkbutton check,
check,
radio {
  background-color: #100f0e;
  border: 1px solid #3a322c;
  color: #ffd7b8;
}

check:checked,
checkbutton check:checked,
radio:checked,
checkbutton radio:checked {
  background-color: @accent;
  border-color: @accent;
  color: #1a0f06;
}

switch {
  background-color: #221d19;
  border: 1px solid #3a322c;
}

switch:checked {
  background-color: @accent;
  border-color: @accent;
}

switch > slider {
  background-color: #cbc3bb;
}

progressbar trough {
  background-color: #100f0e;
  border: 1px solid #2b2521;
}

progressbar progress,
levelbar block.filled {
  background-color: @accent;
}

separator {
  background-color: @line;
}

link,
button.link {
  color: @accent;
}

spinbutton button {
  background-color: transparent;
  border: none;
  color: @text_dim;
}

textview text selection {
  background-color: rgba(255, 122, 41, 0.30);
}

scrollbar {
  background-color: transparent;
}

scrollbar slider {
  background-color: #2a241f;
}

scrollbar slider:hover {
  background-color: #3b322a;
}

"""


def generate() -> str:
    css = BASE_CSS.read_text()
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)

    out: list[str] = []
    out.append("/* IMSIsting — Ember\n"
               " *\n"
               " * GENERATED by tools/gen-theme.py from native/resources/style.css.\n"
               " * Do not hand-edit: the next run overwrites it. Change the palette or\n"
               " * the derivation in the generator, then regenerate.\n"
               " *\n"
               " * The same desk, one temperature over: near-black surfaces with a warm\n"
               " * bias, a single ember accent where the bench had cyan, and every status\n"
               " * hue left alone so a warning still reads as a warning.\n"
               " */\n\n"
               "/* ── the palette ──────────────────────────────────────────────── */\n")

    seen = set()
    for name, value in DEFINE_RE.findall(css):
        value = value.strip()
        seen.add(name)
        out.append(f"@define-color {name} {PALETTE.get(name) or convert_value(value)};\n")
    for name, value in PALETTE.items():
        if name not in seen:
            out.append(f"@define-color {name} {value};\n")
    out.append("\n")

    # Every rule that names a colour, restated in the new palette. A rule whose
    # declarations are all colour-free is skipped: the base sheet still paints
    # it, and copying shape rules would be copying the design.
    rules = 0
    decls = 0
    for selector, body in split_rules(css):
        if not body.strip():
            continue
        keep = []
        for decl in body.split(";"):
            if ":" not in decl:
                continue
            prop, _, value = decl.partition(":")
            prop, value = prop.strip(), value.strip()
            if not prop or not value or not has_colour(value):
                continue
            keep.append(f"  {prop}: {convert_value(value)};")
        if not keep:
            continue
        rules += 1
        decls += len(keep)
        out.append(f"{selector} {{\n" + "\n".join(keep) + "\n}\n\n")

    out.append(f"/* {rules} rule(s), {decls} declaration(s), derived from style.css */\n")
    out.append(CHROME)
    print(f"gen-theme: {rules} rules, {decls} declarations", file=sys.stderr)
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="derive a theme stylesheet")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when the file on disk differs from a fresh run")
    ap.add_argument("--map", metavar="COLOUR",
                    help="print what one colour becomes and exit")
    args = ap.parse_args()

    if args.map:
        value = args.map.strip()
        if not (HEX_RE.search(value) or RGBA_RE.search(value)):
            print(f"gen-theme: not a colour: {value}", file=sys.stderr)
            return 2
        print(convert_value(value))
        return 0

    text = generate()
    if args.check:
        current = OUT_CSS.read_text() if OUT_CSS.exists() else ""
        if current != text:
            print(f"gen-theme: {OUT_CSS.relative_to(ROOT)} is stale", file=sys.stderr)
            return 1
        print("gen-theme: up to date", file=sys.stderr)
        return 0
    OUT_CSS.write_text(text)
    print(f"wrote {OUT_CSS.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
