#!/usr/bin/env python3
"""mk-module-icon.py — put an icon into the set's convention, or resize one.

Every module icon under native/resources/icons/symbolic is drawn on ONE 256x256
canvas, in ONE colour, with the artwork inset by a 4px margin so no glyph
touches the edge. The launcher draws that geometry as-is, so a glyph in another
colour, on another canvas, or with a background baked in is the odd one out and
reads as a bug in the interface.

Three things break the convention, and this tool does all three:

  trace   a raster (jpeg/png) — knock the background out by luminance, thicken
          what is left until it survives being drawn at 24px, trace it with
          potrace, and wrap the result as a symbolic icon
  adopt   an SVG from somewhere else — keep its paths, drop its colour, and
          re-fit it onto the canvas
  scale   an icon already in the set — grow or shrink the artwork about the
          canvas centre. --fit caps the factor so the ink still clears the
          margin, and re-centres the glyph while it does

How big the ink is comes from a render, never from a guess and never from a
coordinate read: the file is rasterised at 256px and the alpha bbox is taken.
That is the only measurement that survives the unit soup in these files — one
family nests an inner <svg viewBox>, another is a flat 1024-square transform,
and a traced source can carry its width in points rather than pixels.

Usage:
  tools/mk-module-icon.py scale <module> <factor> [--fit]
  tools/mk-module-icon.py adopt <source.svg> <module> [--color currentColor]
  tools/mk-module-icon.py trace <raster> <module> [--threshold N] [--dilate N]
                                     [--stroke F]
  tools/mk-module-icon.py measure <file.svg>

<module> is the registry id — 07_gsm_attack writes
imsisting-07_gsm_attack-symbolic.svg. Exit: 0 wrote · 1 I/O · 2 refused · 3 a
tool this needs is not installed.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "native", "resources", "icons", "symbolic")

CANVAS = 256.0
SAFE = 4.0                     # the set's inset: ink lives in 4..252
FIT = CANVAS - 2 * SAFE        # 248
COLOR = "#c8d4e2"              # the set's single colour, read off the icons

HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" '
        'viewBox="0 0 256 256" fill="%s">\n')


def head(colour):
    return HEAD % colour

RE_BOX = re.compile(
    r'<g transform="translate\(([-\d.]+) ([-\d.]+)\) scale\(([-\d.]+)\)"')
RE_INNER = re.compile(
    r'<svg x="([-\d.]+)" y="([-\d.]+)" width="([-\d.]+)" height="([-\d.]+)"')


def die(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def need(binary, why):
    if not shutil.which(binary):
        die("%s is not installed — %s" % (binary, why), 3)


def pillow():
    try:
        from PIL import Image, ImageFilter
        import PIL.Image as _I
        return Image, ImageFilter, _I.Dither
    except ImportError:
        die("Pillow is not installed (python3 -m pip install Pillow)", 3)


def path_for(module):
    return os.path.join(OUT, "imsisting-%s-symbolic.svg" % module)


# ── measurement: render, then read the alpha bbox ───────────────────────
def ink_box(path):
    """(x0, y0, w, h) of the drawn pixels on the 256 canvas."""
    need("inkscape", "the ink box is measured from a render, not guessed")
    Image, _f, _d = pillow()
    with tempfile.TemporaryDirectory() as td:
        png = os.path.join(td, "r.png")
        subprocess.run(["inkscape", "--export-type=png",
                        "--export-filename=" + png, "--export-width=256", path],
                       check=True, capture_output=True)
        im = Image.open(png).convert("RGBA")
        box = im.getchannel("A").point(lambda v: 255 if v > 40 else 0).getbbox()
    if not box:
        die("%s draws nothing" % path)
    x0, y0, x1, y1 = box
    return float(x0), float(y0), float(x1 - x0), float(y1 - y0)


# ── the two wrapper shapes the set uses ─────────────────────────────────
def read_box(text):
    """-> (kind, raster box in canvas units).

    "inner": <svg x y width height viewBox> — a foreign viewBox on the canvas
    "flat":  <g translate(tx ty) scale(s)> — a 1024-square traced raster
    """
    m = RE_INNER.search(text)
    if m:
        return "inner", tuple(float(v) for v in m.groups())
    m = RE_BOX.search(text)
    if m:
        tx, ty, s = (float(v) for v in m.groups())
        return "flat", (tx, ty, 1024.0 * s, 1024.0 * s)
    die('no wrapper this tool knows: neither <svg x=... width=...> nor '
        '<g transform="translate(...) scale(...)">')


def write_box(text, kind, box):
    x, y, w, h = box
    if kind == "inner":
        new = '<svg x="%.2f" y="%.2f" width="%.2f" height="%.2f"' % (x, y, w, h)
        return RE_INNER.sub(lambda _m: new, text, count=1)
    old = RE_BOX.search(text).group(0)
    new = '<g transform="translate(%.4f %.4f) scale(%.6f)"' % (x, y, w / 1024.0)
    return text.replace(old, new, 1)


def boxed(ink, canvas_box, factor, recentre):
    """The raster box after a factor, about the canvas centre or the ink."""
    x, y, w, h = canvas_box
    nw, nh = w * factor, h * factor
    if recentre:
        ix = (ink[0] + ink[2] / 2 - x) / w     # ink centre as a box fraction
        iy = (ink[1] + ink[3] / 2 - y) / h
        return (CANVAS / 2 - ix * nw, CANVAS / 2 - iy * nh, nw, nh)
    return (CANVAS / 2 - (CANVAS / 2 - x) * factor,
            CANVAS / 2 - (CANVAS / 2 - y) * factor, nw, nh)


# ── commands ────────────────────────────────────────────────────────────
def cmd_measure(path):
    i = ink_box(path)
    print("ink\t%.2f\t%.2f\t%.2f\t%.2f" % i)
    inside = (i[0] >= 0 and i[1] >= 0 and
              i[0] + i[2] <= CANVAS and i[1] + i[3] <= CANVAS)
    print("inside_canvas\t%s" % ("yes" if inside else "no"))
    return 0


def cmd_scale(module, factor, fit):
    path = path_for(module)
    if not os.path.exists(path):
        die("no such icon: %s" % path, 1)
    text = open(path).read()
    kind, box = read_box(text)
    ink = ink_box(path)
    f = float(factor)
    recentre = False
    if fit:
        capped = min(FIT / ink[2], FIT / ink[3])
        if f > capped:
            f = capped
            recentre = True
    open(path, "w").write(write_box(text, kind, boxed(ink, box, f, recentre)))
    print("icon\t%s" % os.path.basename(path))
    print("factor\t%.4f" % f)
    print("ink_before\t%.1f\t%.1f" % (ink[2], ink[3]))
    print("ink_after\t%.1f\t%.1f" % (ink[2] * f, ink[3] * f))
    return 0


def cmd_adopt(src, module, colour):
    if not os.path.exists(src):
        die("no such file: %s" % src, 1)
    text = open(src).read()
    body = re.sub(r"(?s)<\?xml.*?\?>", "", text)
    body = re.sub(r"(?s)<!DOCTYPE.*?>", "", body)
    body = re.sub(r"(?s)<metadata>.*?</metadata>", "", body)
    body = re.sub(r"(?s)<svg\b[^>]*>", "", body, count=1)
    body = body.rsplit("</svg>", 1)[0]
    # Colour belongs to the set, not to the file that walked in. Dropping the
    # attributes lets the wrapper's fill and stroke be inherited.
    body = re.sub(r'\sfill="[^"]*"', "", body)
    body = re.sub(r'\sstroke="[^"]*"', "", body)
    body = body.strip()

    ink = ink_box(src)                      # rendered at 256: measures the
    # source's own canvas, so it has to be mapped back into the user-unit space
    # the paths are written in. A source whose viewBox is 500 wide renders at
    # 500/256 user units per pixel; without this the glyph comes out 2x too big
    # and is clipped by the canvas.
    vb = re.search(r'viewBox="([-\d.]+)[ ,]+([-\d.]+)[ ,]+([-\d.]+)[ ,]+([-\d.]+)"',
                   re.search(r"<svg\b[^>]*>", text).group(0))
    per_px = float(vb.group(3)) / CANVAS if vb else 1.0
    ink = tuple(v * per_px for v in ink)
    f = FIT / max(ink[2], ink[3])
    tx = CANVAS / 2 - f * (ink[0] + ink[2] / 2)
    ty = CANVAS / 2 - f * (ink[1] + ink[3] / 2)
    out = (head(colour) +
           '<g transform="translate(%.4f %.4f) scale(%.6f)" fill="%s" '
           'stroke="none">\n%s\n</g>\n</svg>\n' % (tx, ty, f, colour, body))
    dest = path_for(module)
    open(dest, "w").write(out)
    print("icon\t%s" % os.path.basename(dest))
    print("source\t%s" % os.path.basename(src))
    print("ink_after\t%.1f\t%.1f" % (ink[2] * f, ink[3] * f))
    return 0


def cmd_trace(raster, module, threshold, dilate, stroke, invert):
    need("potrace", "the raster has to be traced to become a symbolic icon")
    Image, ImageFilter, Dither = pillow()
    im = Image.open(raster).convert("L")
    # The subject is the bright line art; the background goes by luminance,
    # which is what "remove the background" means for a flat plate.
    mask = im.point(lambda v: 255 if (v > threshold) != invert else 0)
    if dilate:
        # Line art drawn for a poster is thinner than a 24px icon can show.
        mask = mask.filter(ImageFilter.MaxFilter(dilate * 2 + 1))
    box = mask.getbbox()
    if not box:
        die("%s has no ink above luminance %d" % (raster, threshold))
    mask = mask.crop(box)
    w, h = mask.size
    with tempfile.TemporaryDirectory() as td:
        pbm = os.path.join(td, "mask.pbm")
        # potrace traces the BLACK regions of a PBM, so the ink is written
        # black on a white ground. Writing the mask as it stands traces the
        # background instead, and the glyph comes back as a hole in a slab.
        mask.point(lambda v: 0 if v else 255).convert(
            "1", dither=Dither.NONE).save(pbm)
        svg = os.path.join(td, "traced.svg")
        subprocess.run(["potrace", "-s", "-o", svg, "--flat", "--turdsize", "2",
                        pbm], check=True, capture_output=True)
        traced = open(svg).read()
    paths = re.findall(r"<path[^>]*/>", traced)
    if not paths:
        die("potrace produced no path from %s" % raster, 1)
    inner = re.search(r'<g transform="translate\(([-\d.]+),[-\d.]+\) '
                      r'scale\(([-\d.]+),([-\d.]+)\)"', traced)
    if not inner:
        die("potrace output has no transform this tool knows", 1)
    gtrans = inner.group(0).rstrip(">").lstrip("<g ")

    f = FIT / max(w, h)
    tx = CANVAS / 2 - f * (w / 2)
    ty = CANVAS / 2 - f * (h / 2)
    # A hairline traced at poster resolution is invisible once the canvas is
    # drawn at 24px, so the paths carry a stroke as well as a fill.
    out = (head(COLOR) +
           '<g transform="translate(%.4f %.4f) scale(%.6f)" fill="%s" '
           'stroke="%s" stroke-width="%.2f" stroke-linejoin="round">\n'
           % (tx, ty, f, COLOR, COLOR, stroke) +
           '<g %s>\n%s\n</g>\n</g>\n</svg>\n' % (gtrans, "\n".join(paths)))
    dest = path_for(module)
    open(dest, "w").write(out)
    print("icon\t%s" % os.path.basename(dest))
    print("source\t%s" % os.path.basename(raster))
    print("raster\t%d\t%d" % (w, h))
    print("ink_after\t%.1f\t%.1f" % (w * f, h * f))
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    if cmd == "measure":
        return cmd_measure(args[0])
    if cmd == "scale":
        if len(args) < 2:
            die("usage: scale <module> <factor> [--fit]")
        return cmd_scale(args[0], args[1], "--fit" in args)
    if cmd == "adopt":
        if len(args) < 2:
            die("usage: adopt <source.svg> <module> [--color currentColor]")
        colour = COLOR
        if "--color" in args:
            colour = args[args.index("--color") + 1]
            if colour != "currentColor" and not re.fullmatch(r"#[0-9a-fA-F]{6}", colour):
                die("--color takes currentColor or a #rrggbb value, not %r" % colour)
        return cmd_adopt(args[0], args[1], colour)
    if cmd == "trace":
        if len(args) < 2:
            die("usage: trace <raster> <module> [--threshold N] [--dilate N] "
                "[--stroke F]")
        threshold, dilate, stroke = 96, 2, 0.8
        if "--threshold" in args:
            threshold = int(args[args.index("--threshold") + 1])
        if "--dilate" in args:
            dilate = int(args[args.index("--dilate") + 1])
        if "--stroke" in args:
            stroke = float(args[args.index("--stroke") + 1])
        return cmd_trace(args[0], args[1], threshold, dilate, stroke,
                         "--invert" in args)
    die("unknown command %s (measure, adopt, scale, trace)" % cmd)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
