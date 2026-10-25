#!/usr/bin/env python3
"""gen-basemap — turn the checked-in Natural Earth GeoJSON into the flat binary
the map page renders, and trim the populated-places layer to readable labels.

Source files live in native/resources/basemap/ and are Natural Earth 1:110m,
which is public domain: no attribution, no share-alike, nothing to carry into
the tree. They are checked in so a build never needs the network; this script
is what turns them into something a renderer can walk without a JSON parser.

Usage:
    tools/gen-basemap.py                 # regenerate every layer in place
    tools/gen-basemap.py --check         # exit 1 if any output is stale
    tools/gen-basemap.py --measure       # print counts and sizes, write nothing

Binary layout (little endian, "NEBM" v1):

    magic        4s   "NEBM"
    version      u8   1
    kind         u8   0 = polygon parts, 1 = line parts, 2 = points
    reserved     u8   zero
    bounds       i32 * 4   min_lon, min_lat, max_lon, max_lat, in 1e-4 degrees
    part_count   u32
    point_count  u32
    index        part_count * (u32 offset, u32 length)   into the point array
    points       point_count * (i32 lon, i32 lat)         1e-4 degrees

1e-4 degrees is about 11 m at the equator: two orders finer than the 1:110m
geometry itself, so the quantisation is never what limits a zoom.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASEMAP = ROOT / "native" / "resources" / "basemap"

MAGIC = b"NEBM"
VERSION = 1
KIND_POLYGON, KIND_LINE, KIND_POINT = 0, 1, 2
SCALE = 10000.0  # degrees -> 1e-4

# name, source, output, kind, label filter (None = keep every feature)
LAYERS = [
    ("land", "ne_110m_land.geojson", "land.bin", KIND_POLYGON, None),
    ("coastline", "ne_110m_coastline.geojson", "coastline.bin", KIND_LINE, None),
    ("countries", "ne_110m_admin_0_countries.geojson", "countries.bin", KIND_LINE, None),
    ("places", "ne_110m_populated_places.geojson", "places.bin", KIND_POINT, 3),
]


def flatten(geom: dict) -> list[list[tuple[float, float]]]:
    """GeoJSON geometry -> a list of coordinate parts.

    Polygon rings are emitted as closed parts; the renderer fills those. A ring
    that is not closed in the source is closed here, because a fill that is not
    closed is a fill cairo silently drops.
    """
    kind = geom.get("type")
    if kind == "Polygon":
        rings = geom.get("coordinates", [])
        return [list(map(tuple, ring)) for ring in rings]
    if kind == "MultiPolygon":
        parts = []
        for poly in geom.get("coordinates", []):
            parts.extend(list(map(tuple, ring)) for ring in poly)
        return parts
    if kind == "LineString":
        return [list(map(tuple, geom.get("coordinates", [])))]
    if kind == "MultiLineString":
        return [list(map(tuple, line)) for line in geom.get("coordinates", [])]
    if kind == "Point":
        return [[tuple(geom.get("coordinates", [0, 0]))]]
    if kind == "MultiPoint":
        return [[tuple(c)] for c in geom.get("coordinates", [])]
    return []


def quantise(points: list[tuple[float, float]], closed: bool) -> list[tuple[int, int]]:
    out = []
    for lon, lat in points:
        out.append((int(round(lon * SCALE)), int(round(lat * SCALE))))
    if closed and len(out) >= 3 and out[0] != out[-1]:
        out.append(out[0])
    return out


def build(src: Path, kind: int) -> tuple[bytes, int, int]:
    doc = json.loads(src.read_text())
    parts: list[list[tuple[int, int]]] = []
    for feature in doc.get("features", []):
        geom = feature.get("geometry") or {}
        for raw in flatten(geom):
            if len(raw) < (1 if kind == KIND_POINT else 2):
                continue
            q = quantise(raw, closed=(kind == KIND_POLYGON))
            if kind == KIND_POLYGON and len(q) < 4:
                continue
            parts.append(q)

    points: list[tuple[int, int]] = []
    index: list[tuple[int, int]] = []
    for part in parts:
        index.append((len(points), len(part)))
        points.extend(part)
    if not points:
        raise SystemExit(f"gen-basemap: {src.name} produced no geometry")

    lons = [p[0] for p in points]
    lats = [p[1] for p in points]
    header = MAGIC + struct.pack(
        "<BBBiiiiII",
        VERSION, kind, 0,
        min(lons), min(lats), max(lons), max(lats),
        len(index), len(points),
    )
    idx = b"".join(struct.pack("<II", off, ln) for off, ln in index)
    pts = b"".join(struct.pack("<ii", lon, lat) for lon, lat in points)
    return header + idx + pts, len(index), len(points)


def build_places_tsv(src: Path, max_rank: int) -> bytes:
    doc = json.loads(src.read_text())
    rows = ["name\tlat\tlon\trank\tsov0\tadm0"]
    for feature in doc.get("features", []):
        props = feature.get("properties") or {}
        try:
            rank = int(props.get("SCALERANK", 99))
        except (TypeError, ValueError):
            continue
        if rank > max_rank:
            continue
        lon, lat = (feature.get("geometry") or {}).get("coordinates", [0, 0])[:2]
        name = (props.get("NAME") or "").replace("\t", " ").strip()
        if not name:
            continue
        rows.append(
            "\t".join([
                name, f"{lat:.4f}", f"{lon:.4f}", str(rank),
                (props.get("SOV0NAME") or "").strip(),
                (props.get("ADM0NAME") or "").strip(),
            ])
        )
    return ("\n".join(rows) + "\n").encode()


def read_meta(path: Path) -> tuple[int, int]:
    with path.open("rb") as fh:
        head = fh.read(4 + 27)
    if head[:4] != MAGIC:
        raise SystemExit(f"gen-basemap: {path.name} is not a NEBM file")
    _, _kind, _res, _a, _b, _c, _d, parts, points = struct.unpack("<BBBiiiiII", head[4:])
    return parts, points


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="report stale outputs and exit 1; write nothing")
    ap.add_argument("--measure", action="store_true",
                    help="print what would be written; write nothing")
    args = ap.parse_args(argv)

    stale = False
    total = 0
    for name, src_name, out_name, kind, rank in LAYERS:
        src = BASEMAP / src_name
        out = BASEMAP / out_name
        if not src.exists():
            print(f"gen-basemap: missing source {src.relative_to(ROOT)}", file=sys.stderr)
            return 1
        blob, parts, points = build(src, kind)
        total += len(blob)
        tsv_name = "places.tsv" if name == "places" else None
        tsv = build_places_tsv(src, rank) if rank is not None else None

        if args.measure:
            extra = f" tsv={len(tsv):7d} rows={tsv.count(b'\\n') - 1}" if tsv else ""
            print(f"{name:10s} parts={parts:6d} points={points:7d} bin={len(blob):8d}{extra}")
            continue
        if args.check:
            same = (out.exists() and out.read_bytes() == blob
                    and (tsv is None or (BASEMAP / tsv_name).read_bytes() == tsv))
            print(f"{name:10s} {'up to date' if same else 'STALE'}")
            stale = stale or not same
            continue
        out.write_bytes(blob)
        print(f"wrote {out.relative_to(ROOT)} ({len(blob)} bytes, {parts} parts, {points} points)")
        if tsv is not None:
            (BASEMAP / tsv_name).write_bytes(tsv)
            print(f"wrote {(BASEMAP / tsv_name).relative_to(ROOT)} ({len(tsv)} bytes)")

    if args.measure:
        print(f"total binary: {total} bytes")
        return 0
    if args.check and stale:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
