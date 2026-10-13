#!/usr/bin/env python3
"""img2ansi — turn an image into terminal art at CLI-splash fidelity.

Two modes:

  half   truecolor half-blocks: each character cell is two vertical pixels
         (fg = top, bg = bottom) using U+2580. This is how a modern CLI splash
         renders a sprite (the Copilot mascot, a photo, a line drawing). It is
         the mode that looks "realistic" in a truecolor terminal.

  ascii  a luminance ramp into characters, optionally tinted a single colour.
         Best for line art (a wireframe on black) or when truecolor is not
         wanted.

Nothing is uploaded and no network is used; the image never leaves the machine.

Examples:
  img2ansi.py ref.png --width 60 --mode half
  img2ansi.py kit.png --width 70 --mode ascii --bits " .:-=+*#%@" --invert --tint 8a7bff
  img2ansi.py kit.png --width 70 --mode ascii --threshold 40 --tint 8a7bff > art.txt
"""

from __future__ import annotations

import argparse
import sys

try:
    from PIL import Image, ImageEnhance, ImageOps
except Exception as exc:  # pragma: no cover - environment guard
    sys.stderr.write("img2ansi: Pillow is required (python3 -m PIL). %s\n" % exc)
    raise SystemExit(3)


def _hex_rgb(s: str) -> tuple[int, int, int]:
    s = s.lstrip("#")
    if len(s) != 6:
        raise argparse.ArgumentTypeError("colour must be RRGGBB")
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


def _flatten(im: Image.Image, bg: tuple[int, int, int]) -> Image.Image:
    """Composite any alpha over a solid background so no transparent pixels
    leak into the terminal as garbage."""
    if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
        im = im.convert("RGBA")
        canvas = Image.new("RGBA", im.size, bg + (255,))
        canvas.alpha_composite(im)
        return canvas.convert("RGB")
    return im.convert("RGB")


def _target_size(im: Image.Image, width: int, half: bool) -> tuple[int, int]:
    # Character cells are about twice as tall as they are wide, and in half
    # mode each cell carries two pixels vertically.
    ar = im.height / im.width if im.width else 1.0
    rows = max(1, int(round(ar * width * (0.5 if half else 0.5))))
    h = rows * 2 if half else rows
    return (width, h)


def emit_half(im: Image.Image, width: int) -> None:
    im = im.resize(_target_size(im, width, True), Image.LANCZOS)
    px = im.load()
    w, h = im.size
    out = []
    for y in range(0, h, 2):
        row = []
        for x in range(w):
            r1, g1, b1 = px[x, y]
            if y + 1 < h:
                r2, g2, b2 = px[x, y + 1]
            else:
                r2, g2, b2 = r1, g1, b1
            row.append(
                "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm\u2580"
                % (r1, g1, b1, r2, g2, b2)
            )
        out.append("".join(row) + "\x1b[0m")
    sys.stdout.write("\n".join(out) + "\n")


def emit_ascii(im: Image.Image, width: int, bits: str, tint, threshold: int) -> None:
    g = im.convert("L")
    g = g.resize(_target_size(g, width, False), Image.LANCZOS)
    px = g.load()
    w, h = g.size
    ramp = bits if bits else " .:-=+*#%@"
    last = len(ramp) - 1
    esc = "\x1b[38;2;%d;%d;%dm" % tint if tint else ""
    reset = "\x1b[0m" if tint else ""
    for y in range(h):
        chars = []
        for x in range(w):
            v = px[x, y]
            if threshold and v <= threshold:
                chars.append(" ")
            else:
                chars.append(ramp[int(v / 255 * last)])
        line = "".join(chars).rstrip()
        sys.stdout.write((esc + line + reset if esc else line) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="image -> terminal art")
    ap.add_argument("image", help="source image (png/jpg/webp/...)")
    ap.add_argument("--width", type=int, default=80, help="columns (default 80)")
    ap.add_argument("--mode", choices=["half", "ascii"], default="half")
    ap.add_argument("--bits", default=" .:-=+*#%@", help="ascii ramp, dark->light")
    ap.add_argument("--invert", action="store_true", help="invert luminance")
    ap.add_argument("--tint", type=_hex_rgb, default=None, help="RRGGBB for ascii mode")
    ap.add_argument("--threshold", type=int, default=0, help="0..255; drop pixels <= this")
    ap.add_argument("--contrast", type=float, default=1.0)
    ap.add_argument("--bg", type=_hex_rgb, default=(0, 0, 0), help="alpha background")
    ap.add_argument("--flip", action="store_true", help="mirror horizontally")
    ap.add_argument("--edges", action="store_true",
                    help="edge-detect first: turn a photo into line art")
    ap.add_argument("--dilate", type=int, default=0,
                    help="grow edges by N px (edges mode)")
    args = ap.parse_args()

    try:
        im = Image.open(args.image)
    except Exception as exc:
        sys.stderr.write("img2ansi: cannot open %s: %s\n" % (args.image, exc))
        return 2

    im = _flatten(im, args.bg)
    if args.flip:
        im = ImageOps.mirror(im)
    if args.contrast != 1.0:
        im = ImageEnhance.Contrast(im).enhance(args.contrast)

    if args.edges:
        from PIL import ImageFilter
        g = ImageOps.autocontrast(im.convert("L")).filter(ImageFilter.FIND_EDGES)
        if args.dilate > 0:
            g = g.filter(ImageFilter.MaxFilter(2 * args.dilate + 1))
        g = ImageOps.autocontrast(g)
        if args.threshold:
            g = g.point(lambda v: 255 if v > args.threshold else 0)
        im = g.convert("RGB")
    elif args.invert:
        im = ImageOps.invert(im)

    if args.mode == "half":
        emit_half(im, args.width)
    else:
        emit_ascii(im, args.width, args.bits, args.tint, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
