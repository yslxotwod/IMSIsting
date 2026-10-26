#!/usr/bin/env python3
"""Turn the findings this tree prints into something a second system can use.

Every detector in the toolkit writes `finding <key> <SEVERITY> <text>` rows into
a loot TSV. Those rows are readable by a person and useless to a SIEM, which is
the gap this tool closes: the same rows become a catalogue, one Sigma rule per
distinct finding, ECS-shaped JSON events, or CEF lines.

The identifiers are stable on purpose. A rule's name is
`imsisting.<module>.<finding key>`, and the Sigma rule id is a UUIDv5 of that
name, so re-exporting a changed tree updates a rule instead of duplicating it.

What this tool does not do: it does not invent detections. A finding exists
because a module printed one, and a module with no findings exports nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

LEVEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
         "LOW": "low", "INFO": "informational"}
UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://imsisting.invalid/detections")


def module_of(path: Path) -> str:
    """The store directory names the module, which is what a rule is scoped to."""
    parent = path.parent.name or "unknown"
    return parent if parent and parent != "loot" else "unknown"


def collect(paths):
    """Yield (module, key, severity, text) for every finding row in the inputs."""
    seen_files = 0
    for p in paths:
        files = sorted(x for x in p.rglob("*.tsv")) if p.is_dir() else [p]
        for f in files:
            seen_files += 1
            try:
                with open(f, "r", errors="replace") as fh:
                    for line in fh:
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) < 3 or parts[0] != "finding":
                            continue
                        key, sev = parts[1], parts[2].upper()
                        text = parts[3] if len(parts) > 3 else ""
                        yield module_of(f), key, sev, text
            except OSError as exc:
                print("warn\tunreadable\t%s\t%s" % (f, exc), file=sys.stderr)
    yield ("__files__", "", "", str(seen_files))


def catalogue(rows):
    agg = {}
    for mod, key, sev, text in rows:
        if mod == "__files__":
            continue
        cur = agg.setdefault((mod, key), {"severity": sev, "text": text, "count": 0})
        cur["count"] += 1
        if LEVEL.get(sev, "informational") != LEVEL.get(cur["severity"], "informational"):
            cur["severity"] = sev
    for (mod, key), v in sorted(agg.items()):
        yield ("finding", "%s.%s" % (mod, key), v["severity"], v["count"], v["text"])


def sigma(mod, key, sev, text):
    name = "imsisting.%s.%s" % (mod, key)
    rid = str(uuid.uuid5(UUID_NS, name))
    level = LEVEL.get(sev, "informational")
    lines = [
        "title: %s" % name,
        "id: %s" % rid,
        "status: experimental",
        "description: %s" % (text.replace("\n", " ") or "Finding reported by %s" % mod),
        "author: IMSIsting",
        "logsource:",
        "    product: imsisting",
        "    service: %s" % mod,
        "detection:",
        "    selection:",
        "        event.dataset: imsisting.%s" % mod,
        "        rule.name: %s" % key,
        "    condition: selection",
        "level: %s" % level,
        "falsepositives:",
        "    - A capture or plan that was replayed on purpose",
        "tags:",
        "    - imsisting.module.%s" % mod,
    ]
    return "\n".join(lines) + "\n"


def ecs(mod, key, sev, count, text):
    return json.dumps({
        "event": {"kind": "alert", "dataset": "imsisting.%s" % mod,
                  "module": mod, "count": count},
        "rule": {"name": key, "id": str(uuid.uuid5(UUID_NS, "imsisting.%s.%s" % (mod, key)))},
        "imsisting": {"severity": LEVEL.get(sev, "informational"),
                      "severity_label": sev, "detail": text},
        "message": text,
        "tags": ["imsisting", "cellular", mod],
    }, sort_keys=True)


def cef(mod, key, sev, count, text):
    esc = lambda s: (s or "").replace("\\", "\\\\").replace("|", "\\|")
    return ("CEF:0|IMSIsting|%s|1.0|%s|%s|%d|msg=%s cnt=%d"
            % (mod, key, esc(text)[:200], {"HIGH": 8, "MEDIUM": 6, "LOW": 3,
                                           "INFO": 1}.get(sev, 1), esc(text), count))


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("paths", nargs="*", help="loot directories or TSV files")
    ap.add_argument("--format", default="catalogue",
                    choices=("catalogue", "sigma", "ecs", "cef", "json"))
    ap.add_argument("--out", help="write sigma rules into this directory")
    ap.add_argument("--root", default=os.environ.get("LOOT_DIR", ""),
                    help="default root when no path is given")
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.paths]
    if not paths and args.root:
        paths = [Path(args.root)]
    if not paths:
        print("ERROR\tno input: give a loot directory, a TSV, or set LOOT_DIR", file=sys.stderr)
        return 2
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print("ERROR\tno such path: %s" % ", ".join(missing), file=sys.stderr)
        return 1

    rows = list(collect(paths))
    files = 0
    for mod, key, sev, text in rows:
        if mod == "__files__":
            files = int(text)
    entries = list(catalogue(rows))

    mods = {e[1].split(".", 1)[0] for e in entries}
    sevs = {}
    for e in entries:
        sevs[e[2]] = sevs.get(e[2], 0) + 1

    if args.format == "catalogue":
        print("files\t%d" % files)
        print("findings\t%d" % len(entries))
        print("modules\t%d" % len(mods))
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in sevs:
                print("severity\t%s\t%d" % (sev, sevs[sev]))
        for e in entries:
            print("\t".join(str(x) for x in e))
        print("verdict\t%s" % ("detections_catalogued" if entries else "nothing_to_export"))
        return 0

    if args.format == "sigma":
        if not args.out:
            print("ERROR\t--out is required for sigma: one file per rule", file=sys.stderr)
            return 2
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        written = 0
        for _tag, name, sev, _count, text in entries:
            mod, key = name.split(".", 1)
            (out / ("imsisting.%s.yml" % name)).write_text(sigma(mod, key, sev, text))
            written += 1
        print("written\t%d" % written)
        print("directory\t%s" % out)
        print("verdict\tsigma_rules_written" if written else "nothing_to_export")
        return 0

    if args.format == "ecs":
        for _tag, name, sev, count, text in entries:
            mod, key = name.split(".", 1)
            print(ecs(mod, key, sev, count, text))
        return 0

    if args.format == "cef":
        for _tag, name, sev, count, text in entries:
            mod, key = name.split(".", 1)
            print(cef(mod, key, sev, count, text))
        return 0

    print(json.dumps([{"module": n.split(".", 1)[0], "finding": n.split(".", 1)[1],
                       "severity": s, "count": c, "detail": t}
                      for _tag, n, s, c, t in entries], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
