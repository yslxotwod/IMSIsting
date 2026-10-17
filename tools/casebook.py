#!/usr/bin/env python3
"""IMSIsting Casebook: shared case/evidence state for CLI modules and GTK.

This is project infrastructure, not a cellular module. It intentionally does
not appear in module_index.tsv. Tables emitted by list commands are strict TSV.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Iterable

ROOT = Path(os.environ.get("IMSISTING_ROOT", Path(__file__).resolve().parent.parent))
STATE = Path(os.environ.get("STATE_DIR", ROOT / "state"))
LOOT = Path(os.environ.get("LOOT_DIR", ROOT / "loot"))
CAPTURES = Path(os.environ.get("CAPTURES_DIR", ROOT / "captures"))
LOGS = Path(os.environ.get("LOGS_DIR", ROOT / "logs"))
CASES = Path(os.environ.get("CASES_DIR", ROOT / "cases"))
BOOK = Path(os.environ.get("CASEBOOK_DIR", STATE / "casebook"))
ACTIVE = BOOK / "active_case"
NODES = BOOK / "nodes.tsv"

TARGET_FIELDS = ["id", "selected", "rat", "plmn", "channel", "cell_id", "area", "pci", "band", "lat", "lon", "label", "first_seen", "last_seen"]
EVIDENCE_FIELDS = ["id", "kind", "module", "path", "bytes", "mtime", "sha256", "tags", "sensitivity", "added"]
TIMELINE_FIELDS = ["time", "severity", "type", "source", "message", "reference"]
ALERT_FIELDS = ["time", "severity", "kind", "source", "message", "evidence", "status"]
OBS_FIELDS = ["time", "node", "target", "rat", "plmn", "channel", "cell_id", "pci", "signal", "lat", "lon", "source"]
NODE_FIELDS = ["name", "host", "transport", "role", "added", "last_seen", "status", "detail"]
BASELINE_FIELDS = ["rat", "plmn", "channel", "cell_id", "pci", "signal"]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean(value: object) -> str:
    return str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")


def slug(value: str) -> str:
    out = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")
    out = re.sub(r"-+", "-", out)
    if not out or out in {".", ".."}:
        raise ValueError("invalid identifier")
    return out


def err(message: str, code: int = 1) -> "NoReturn":
    print(f"ERROR\t{clean(message)}", file=sys.stderr)
    raise SystemExit(code)


def write_table(path: Path, fields: list[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    with tmp.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: clean(row.get(key, "")) for key in fields})
    tmp.replace(path)


def read_table(path: Path, fields: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        write_table(path, fields, [])
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def emit(fields: list[str], rows: Iterable[dict[str, object]]) -> None:
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: clean(row.get(key, "")) for key in fields})


def emit_pairs(**items: object) -> None:
    for key, value in items.items():
        print(f"{clean(key)}\t{clean(value)}")


def init_root() -> None:
    BOOK.mkdir(parents=True, exist_ok=True)
    CASES.mkdir(parents=True, exist_ok=True)
    if not NODES.exists():
        write_table(NODES, NODE_FIELDS, [])


def active_id(required: bool = True) -> str:
    value = ACTIVE.read_text(encoding="utf-8").splitlines()[0].strip() if ACTIVE.exists() else ""
    if required and (not value or not (CASES / value).is_dir()):
        err("no active case; use --case-create or --case-select")
    return value


def case_dir(required: bool = True) -> Path:
    return CASES / active_id(required)


def init_case(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "reports").mkdir(exist_ok=True)
    (path / "exports").mkdir(exist_ok=True)
    for name, fields in (("targets", TARGET_FIELDS), ("evidence", EVIDENCE_FIELDS), ("timeline", TIMELINE_FIELDS), ("alerts", ALERT_FIELDS), ("observations", OBS_FIELDS)):
        file = path / f"{name}.tsv"
        if not file.exists():
            write_table(file, fields, [])


def read_meta(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if (path / "case.tsv").exists():
        for line in (path / "case.tsv").read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("\t")
            result[key] = value
    return result


def write_meta(path: Path, meta: dict[str, object]) -> None:
    text = "".join(f"{clean(key)}\t{clean(value)}\n" for key, value in meta.items())
    tmp = path / f".case.tsv.{os.getpid()}"
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path / "case.tsv")


def timeline_add(severity: str, kind: str, source: str, message: str, reference: str = "-") -> None:
    path = case_dir()
    rows = read_table(path / "timeline.tsv", TIMELINE_FIELDS)
    rows.append({"time": now(), "severity": severity.upper(), "type": kind, "source": source, "message": message, "reference": reference})
    write_table(path / "timeline.tsv", TIMELINE_FIELDS, rows)


def cmd_case_create(args: argparse.Namespace) -> None:
    try:
        ident = slug(args.name)
    except ValueError as exc:
        err(str(exc), 2)
    path = CASES / ident
    if path.exists():
        err(f"case exists: {ident}")
    init_case(path)
    write_meta(path, {"id": ident, "name": args.name, "scope": args.scope, "authorization": args.authorization, "created": now(), "status": "OPEN"})
    ACTIVE.write_text(ident + "\n", encoding="utf-8")
    timeline_add("INFO", "case", "casebook", f"case created: {args.name}", str(path / "case.tsv"))
    emit_pairs(case=ident, path=path, status="OPEN")


def cmd_case_select(args: argparse.Namespace) -> None:
    try:
        ident = slug(args.ident)
    except ValueError as exc:
        err(str(exc), 2)
    path = CASES / ident
    if not path.is_dir():
        err(f"unknown case: {ident}")
    init_case(path)
    ACTIVE.write_text(ident + "\n", encoding="utf-8")
    emit_pairs(active_case=ident)


def cmd_case_list(_: argparse.Namespace) -> None:
    selected = active_id(False)
    rows = []
    for path in sorted(CASES.iterdir() if CASES.exists() else []):
        if not path.is_dir() or not (path / "case.tsv").exists():
            continue
        meta = read_meta(path)
        rows.append({**meta, "selected": "yes" if path.name == selected else "no"})
    emit(["id", "name", "status", "created", "scope", "selected"], rows)


def cmd_case_show(_: argparse.Namespace) -> None:
    path = case_dir()
    for key, value in read_meta(path).items():
        print(f"{clean(key)}\t{clean(value)}")
    emit_pairs(path=path)


def cmd_case_close(_: argparse.Namespace) -> None:
    path = case_dir()
    meta = read_meta(path)
    meta.update(status="CLOSED", closed=now())
    write_meta(path, meta)
    timeline_add("INFO", "case", "casebook", "case closed", str(path / "case.tsv"))
    emit_pairs(status="CLOSED")


def cmd_target_set(args: argparse.Namespace) -> None:
    path = case_dir()
    rows = read_table(path / "targets.tsv", TARGET_FIELDS)
    ident = slug(f"{args.rat}-{args.plmn}-{args.cell_id}")
    stamp = now()
    old = next((row for row in rows if row["id"] == ident), None)
    rows = [row for row in rows if row["id"] != ident]
    for row in rows:
        row["selected"] = "no"
    rows.append({"id": ident, "selected": "yes", "rat": args.rat.upper(), "plmn": args.plmn, "channel": args.channel, "cell_id": args.cell_id, "area": args.area, "pci": args.pci, "band": args.band, "lat": args.lat, "lon": args.lon, "label": args.label, "first_seen": old["first_seen"] if old else stamp, "last_seen": stamp})
    write_table(path / "targets.tsv", TARGET_FIELDS, rows)
    timeline_add("INFO", "target", "casebook", f"selected {args.rat.upper()} cell {args.cell_id}", ident)
    emit_pairs(target=ident, rat=args.rat.upper(), cell_id=args.cell_id)


def cmd_target_select(args: argparse.Namespace) -> None:
    path = case_dir()
    rows = read_table(path / "targets.tsv", TARGET_FIELDS)
    if not any(row["id"] == args.ident for row in rows):
        err(f"unknown target: {args.ident}")
    for row in rows:
        row["selected"] = "yes" if row["id"] == args.ident else "no"
    write_table(path / "targets.tsv", TARGET_FIELDS, rows)
    emit_pairs(target=args.ident)


def cmd_target_clear(_: argparse.Namespace) -> None:
    path = case_dir()
    rows = read_table(path / "targets.tsv", TARGET_FIELDS)
    for row in rows:
        row["selected"] = "no"
    write_table(path / "targets.tsv", TARGET_FIELDS, rows)
    emit_pairs(target="none")


def cmd_targets(args: argparse.Namespace) -> None:
    rows = read_table(case_dir() / "targets.tsv", TARGET_FIELDS)
    if getattr(args, "current", False):
        rows = [row for row in rows if row["selected"] == "yes"]
    emit(TARGET_FIELDS, rows)


def evidence_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".pcap", ".pcapng", ".cap"}: return "pcap"
    if suffix in {".iq", ".cfile", ".cf32", ".cs8", ".cu8", ".bin"}: return "iq"
    if suffix == ".log": return "log"
    if suffix in {".kml", ".geojson", ".gpx"}: return "map"
    if suffix in {".tsv", ".csv", ".json"}: return "data"
    return "artifact"


def module_from_path(path: Path) -> str:
    for root in (LOOT, CAPTURES, LOGS):
        try:
            return path.relative_to(root).parts[0]
        except (ValueError, IndexError):
            pass
    return "unknown"


def add_evidence(path: Path, module: str = "", tags: str = "", sensitivity: str = "sensitive") -> bool:
    if not path.is_file():
        return False
    path = path.resolve()
    case = case_dir()
    rows = read_table(case / "evidence.tsv", EVIDENCE_FIELDS)
    if any(row["path"] == str(path) for row in rows):
        return False
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    stat = path.stat()
    sha = digest.hexdigest()
    rows.append({"id": sha[:16], "kind": evidence_kind(path), "module": module or module_from_path(path), "path": path, "bytes": stat.st_size, "mtime": int(stat.st_mtime), "sha256": sha, "tags": tags, "sensitivity": sensitivity, "added": now()})
    write_table(case / "evidence.tsv", EVIDENCE_FIELDS, rows)
    return True


def cmd_evidence_add(args: argparse.Namespace) -> None:
    path = Path(args.file)
    if not path.is_file():
        err(f"file not found: {path}")
    added = add_evidence(path, args.module, args.tags, args.sensitivity)
    emit_pairs(added="yes" if added else "already-indexed", path=path.resolve())


def cmd_index(_: argparse.Namespace) -> None:
    added = 0
    for root in (LOOT, CAPTURES, LOGS):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and add_evidence(path, tags="indexed"):
                added += 1
    total = len(read_table(case_dir() / "evidence.tsv", EVIDENCE_FIELDS))
    timeline_add("INFO", "evidence", "casebook", f"indexed {added} new files", str(case_dir() / "evidence.tsv"))
    emit_pairs(indexed=added, total=total)


def cmd_evidence(args: argparse.Namespace) -> None:
    rows = read_table(case_dir() / "evidence.tsv", EVIDENCE_FIELDS)
    if args.kind:
        rows = [row for row in rows if row["kind"] == args.kind]
    emit(EVIDENCE_FIELDS, rows)


def cmd_captures(_: argparse.Namespace) -> None:
    rows = [row for row in read_table(case_dir() / "evidence.tsv", EVIDENCE_FIELDS) if row["kind"] in {"pcap", "iq", "log"}]
    emit(EVIDENCE_FIELDS, rows)


def cmd_timeline_add(args: argparse.Namespace) -> None:
    timeline_add(args.severity, args.type, args.source, args.message, args.reference)
    emit_pairs(event="added")


def cmd_timeline(_: argparse.Namespace) -> None:
    emit(TIMELINE_FIELDS, read_table(case_dir() / "timeline.tsv", TIMELINE_FIELDS))


def cmd_correlate(_: argparse.Namespace) -> None:
    path = case_dir()
    rows = read_table(path / "timeline.tsv", TIMELINE_FIELDS)
    seen = {(row["type"], row["reference"]) for row in rows}
    for item in read_table(path / "evidence.tsv", EVIDENCE_FIELDS):
        key = ("evidence", item["path"])
        if key in seen:
            continue
        stamp = dt.datetime.fromtimestamp(int(item["mtime"]), dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        rows.append({"time": stamp, "severity": "INFO", "type": "evidence", "source": item["module"], "message": f"{item['kind']} {item['id']}", "reference": item["path"]})
    rows.sort(key=lambda row: row["time"])
    write_table(path / "timeline.tsv", TIMELINE_FIELDS, rows)
    emit_pairs(timeline=len(rows))


def alert_add(severity: str, kind: str, source: str, message: str, evidence: str = "-") -> None:
    path = case_dir()
    rows = read_table(path / "alerts.tsv", ALERT_FIELDS)
    rows.append({"time": now(), "severity": severity.upper(), "kind": kind, "source": source, "message": message, "evidence": evidence, "status": "OPEN"})
    write_table(path / "alerts.tsv", ALERT_FIELDS, rows)
    timeline_add(severity, "alert", source, message, evidence)


def cmd_alert_add(args: argparse.Namespace) -> None:
    alert_add(args.severity, args.kind, args.source, args.message, args.evidence)
    emit_pairs(alert="added")


def cmd_alerts(_: argparse.Namespace) -> None:
    emit(ALERT_FIELDS, read_table(case_dir() / "alerts.tsv", ALERT_FIELDS))


def cmd_alerts_clear(_: argparse.Namespace) -> None:
    write_table(case_dir() / "alerts.tsv", ALERT_FIELDS, [])
    emit_pairs(alerts=0)


def cmd_baseline(args: argparse.Namespace) -> None:
    source = Path(args.file) if args.file else case_dir() / "observations.tsv"
    if not source.is_file():
        err(f"observation TSV not found: {source}")
    with source.open(newline="", encoding="utf-8", errors="replace") as handle:
        observations = list(csv.DictReader(handle, delimiter="\t"))
    seen: set[tuple[str, ...]] = set()
    rows = []
    for obs in observations:
        key = tuple(obs.get(name, "") for name in BASELINE_FIELDS[:-1])
        if key in seen:
            continue
        seen.add(key)
        rows.append({name: obs.get(name, "") for name in BASELINE_FIELDS})
    write_table(case_dir() / "baseline.tsv", BASELINE_FIELDS, rows)
    emit_pairs(baseline_cells=len(rows))


def cmd_ids_scan(args: argparse.Namespace) -> None:
    baseline_file = case_dir() / "baseline.tsv"
    source = Path(args.file)
    if not baseline_file.is_file():
        err("no baseline; use --baseline-build")
    if not source.is_file():
        err(f"observation TSV not found: {source}")
    baseline = {tuple(row[name] for name in BASELINE_FIELDS[:-1]) for row in read_table(baseline_file, BASELINE_FIELDS)}
    with source.open(newline="", encoding="utf-8", errors="replace") as handle:
        observations = list(csv.DictReader(handle, delimiter="\t"))
    count = 0
    for obs in observations:
        key = tuple(obs.get(name, "") for name in BASELINE_FIELDS[:-1])
        if key not in baseline:
            message = f"new {obs.get('rat','?')} cell {obs.get('cell_id','?')} on {obs.get('channel','?')} PLMN {obs.get('plmn','?')} PCI {obs.get('pci','?')}"
            alert_add("HIGH", "unknown-cell", "ids", message, str(source.resolve()))
            count += 1
    emit_pairs(new_alerts=count)


def cmd_observation_add(args: argparse.Namespace) -> None:
    path = case_dir()
    rows = read_table(path / "observations.tsv", OBS_FIELDS)
    rows.append({"time": now(), "node": args.node, "target": args.target, "rat": args.rat, "plmn": args.plmn, "channel": args.channel, "cell_id": args.cell_id, "pci": args.pci, "signal": args.signal, "lat": args.lat, "lon": args.lon, "source": args.source})
    write_table(path / "observations.tsv", OBS_FIELDS, rows)
    emit_pairs(observation=len(rows))


def cmd_observations(_: argparse.Namespace) -> None:
    emit(OBS_FIELDS, read_table(case_dir() / "observations.tsv", OBS_FIELDS))


def cmd_observations_geojson(args: argparse.Namespace) -> None:
    out = Path(args.file) if args.file else case_dir() / "exports" / "observations.geojson"
    features = []
    for row in read_table(case_dir() / "observations.tsv", OBS_FIELDS):
        try:
            lon, lat = float(row["lon"]), float(row["lat"])
        except (TypeError, ValueError):
            continue
        properties = {key: value for key, value in row.items() if key not in {"lat", "lon"}}
        features.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [lon, lat]}, "properties": properties})
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"type": "FeatureCollection", "features": features}, indent=2) + "\n", encoding="utf-8")
    emit_pairs(map=out, points=len(features))


def ue_agent(serial: str, *arguments: str) -> subprocess.CompletedProcess:
    """Run tools/ue_agent.sh against one handset.

    The adb command shapes live in that file, not here: two copies of "how do
    you ask Android for the IMEI" is two places to be wrong.  UE_SERIAL is how
    a serial reaches it, which is the same variable a human would set.
    """
    script = ROOT / "tools" / "ue_agent.sh"
    environment = dict(os.environ)
    environment["UE_SERIAL"] = serial
    return subprocess.run(["bash", str(script), *arguments], capture_output=True,
                          text=True, timeout=40, check=False, env=environment)


def cmd_node_add(args: argparse.Namespace) -> None:
    try:
        ident = slug(args.name)
    except ValueError as exc:
        err(str(exc), 2)
    rows = [row for row in read_table(NODES, NODE_FIELDS) if row["name"] != ident]
    rows.append({"name": ident, "host": args.host, "transport": args.transport, "role": args.role, "added": now(), "last_seen": "-", "status": "UNKNOWN", "detail": "-"})
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=ident)


def cmd_node_remove(args: argparse.Namespace) -> None:
    rows = [row for row in read_table(NODES, NODE_FIELDS) if row["name"] != args.name]
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(removed=args.name)


def cmd_nodes(_: argparse.Namespace) -> None:
    emit(NODE_FIELDS, read_table(NODES, NODE_FIELDS))


def cmd_node_collect(args: argparse.Namespace) -> None:
    """Collect an explicitly named file; never dispatch a remote command."""
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    destination = case_dir() / "exports" / "nodes" / args.name
    destination.mkdir(parents=True, exist_ok=True)
    source = args.remote_path
    target = destination / Path(source).name
    try:
        if node["transport"] == "local":
            shutil.copy2(Path(source), target)
        elif node["transport"] == "ssh":
            subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                            "--", f"{node['host']}:{source}", str(target)],
                           timeout=30, check=True)
        elif node["transport"] == "adb":
            result = ue_agent(node["host"], "--collect", source, str(destination))
            if result.returncode != 0:
                err(f"adb pull failed: {(result.stderr or result.stdout).strip()}")
        else:
            err(f"unsupported transport: {node['transport']}")
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        err(f"collection failed: {exc}")
    added = add_evidence(target, module=f"node:{args.name}", tags="remote-collection")
    timeline_add("INFO", "node-collection", args.name,
                 f"collected {source}", str(target))
    emit_pairs(collected=target, indexed="yes" if added else "already-indexed")


def cmd_node_probe(args: argparse.Namespace) -> None:
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    if node["transport"] == "local":
        usage = shutil.disk_usage(ROOT)
        detail = f"host={socket.gethostname()} free={usage.free}"
        online = True
    elif node["transport"] == "ssh":
        try:
            result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--", node["host"], "printf 'host=%s uptime=%s' \"$(hostname)\" \"$(cut -d' ' -f1 /proc/uptime)\""], capture_output=True, text=True, timeout=8, check=False)
            detail = (result.stdout or result.stderr).strip()
            online = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail, online = str(exc), False
    elif node["transport"] == "adb":
        # role=ue: the host column is the adb serial (or "usb" for the only one
        # attached). ue_agent reports the verdict; a phone that is absent, or
        # present but unauthorised, is OFFLINE with the reason in the detail.
        try:
            result = ue_agent(node["host"], "--probe")
            pairs = dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)
            state = pairs.get("state", "unknown")
            online = state == "device"
            detail = " ".join(f"{key}={value}" for key, value in pairs.items() if key in {"serial", "state", "version"})
            if not detail:
                detail = (result.stderr or "ue_agent returned nothing").strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail, online = str(exc), False
    else:
        err(f"unsupported transport: {node['transport']}")
    node.update(last_seen=now(), status="ONLINE" if online else "OFFLINE", detail=clean(detail))
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=args.name, status=node["status"], detail=node["detail"])
    if not online:
        raise SystemExit(1)


def redact_text(value: object) -> str:
    """Redact common subscriber/device identifiers in shareable reports."""
    text = str(value)
    patterns = (
        (r"(?i)(?:imsi|supi)[ :=_-]*([0-9]{5,16})", r"IMSI:[REDACTED]"),
        (r"(?i)(?:imei|imeisv)[ :=_-]*([0-9]{14,17})", r"IMEI:[REDACTED]"),
        (r"(?i)(?:msisdn)[ :=_+-]*([0-9]{7,15})", r"MSISDN:[REDACTED]"),
        (r"(?i)(?:suci)[ :=_-]*([A-Za-z0-9._:-]{8,})", r"SUCI:[REDACTED]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def redact_object(value: object) -> object:
    if isinstance(value, dict):
        return {key: redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    return redact_text(value)


def report_object(full: bool = False) -> dict[str, object]:
    path = case_dir()
    result = {"case": read_meta(path), "targets": read_table(path / "targets.tsv", TARGET_FIELDS), "evidence": read_table(path / "evidence.tsv", EVIDENCE_FIELDS), "timeline": read_table(path / "timeline.tsv", TIMELINE_FIELDS), "alerts": read_table(path / "alerts.tsv", ALERT_FIELDS), "observations": read_table(path / "observations.tsv", OBS_FIELDS), "nodes": read_table(NODES, NODE_FIELDS)}
    return result if full else redact_object(result)


def report_path(fmt: str, requested: str | None) -> Path:
    path = case_dir()
    return Path(requested) if requested else path / "reports" / f"{path.name}_{dt.datetime.now():%Y%m%d_%H%M%S}.{fmt}"


def cmd_report_json(args: argparse.Namespace) -> None:
    out = report_path("json", args.file)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report_object(args.full), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    emit_pairs(report=out)


def cmd_report_tsv(args: argparse.Namespace) -> None:
    out = report_path("tsv", args.file)
    out.parent.mkdir(parents=True, exist_ok=True)
    obj = report_object(args.full)
    rows = []
    rows.extend({"section": "case", "key": key, "value": value} for key, value in obj["case"].items())
    for section in ("targets", "alerts", "evidence", "timeline", "observations", "nodes"):
        for index, row in enumerate(obj[section], 1):
            rows.append({"section": section, "key": index, "value": json.dumps(row, ensure_ascii=False, separators=(",", ":"))})
    write_table(out, ["section", "key", "value"], rows)
    emit_pairs(report=out)


def cmd_report_html(args: argparse.Namespace) -> None:
    out = report_path("html", args.file)
    out.parent.mkdir(parents=True, exist_ok=True)
    obj = report_object(args.full)
    meta = obj["case"]
    chunks = ["<!doctype html><meta charset='utf-8'><style>body{font:14px system-ui;max-width:1200px;margin:40px auto;color:#182230}table{border-collapse:collapse;width:100%;margin-bottom:28px}th,td{border:1px solid #ccd5df;padding:6px;text-align:left;vertical-align:top}th{background:#edf3f8}code{font-size:12px;overflow-wrap:anywhere}.HIGH,.CRITICAL{color:#a00;font-weight:bold}</style>", f"<h1>IMSIsting Case: {html.escape(meta.get('name',''))}</h1>", f"<p><b>Scope:</b> {html.escape(meta.get('scope',''))}<br><b>Authorization:</b> {html.escape(meta.get('authorization',''))}<br><b>Status:</b> {html.escape(meta.get('status',''))}</p>"]
    for section in ("targets", "alerts", "evidence", "timeline", "observations", "nodes"):
        rows = obj[section]
        chunks.append(f"<h2>{html.escape(section.title())}</h2>")
        if not rows:
            chunks.append("<p>None recorded.</p>")
            continue
        fields = list(rows[0])
        chunks.append("<table><thead><tr>" + "".join(f"<th>{html.escape(f)}</th>" for f in fields) + "</tr></thead><tbody>")
        for row in rows:
            chunks.append("<tr>" + "".join(f"<td class='{html.escape(str(row.get('severity','')))}'><code>{html.escape(str(row.get(f,'')))}</code></td>" for f in fields) + "</tr>")
        chunks.append("</tbody></table>")
    out.write_text("".join(chunks), encoding="utf-8")
    emit_pairs(report=out)


def cmd_reports(_: argparse.Namespace) -> None:
    rows = []
    for path in sorted((case_dir() / "reports").glob("*")):
        if path.is_file():
            stat = path.stat()
            rows.append({"path": path, "bytes": stat.st_size, "mtime": int(stat.st_mtime)})
    emit(["path", "bytes", "mtime"], rows)


def cmd_status(_: argparse.Namespace) -> None:
    ident = active_id(False)
    targets = evidence = alerts = 0
    if ident and (CASES / ident).is_dir():
        init_case(CASES / ident)
        targets = len(read_table(CASES / ident / "targets.tsv", TARGET_FIELDS))
        evidence = len(read_table(CASES / ident / "evidence.tsv", EVIDENCE_FIELDS))
        alerts = len(read_table(CASES / ident / "alerts.tsv", ALERT_FIELDS))
    emit_pairs(active_case=ident or "none", cases=sum(1 for path in CASES.iterdir() if path.is_dir()), targets=targets, evidence=evidence, alerts=alerts, nodes=len(read_table(NODES, NODE_FIELDS)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IMSIsting Casebook: cases, targets, evidence, alerts, nodes and reports")
    sub = parser.add_subparsers(dest="command", required=True)
    def add(name: str, function, *arguments):
        item = sub.add_parser(name)
        for flags, options in arguments:
            item.add_argument(*flags, **options)
        item.set_defaults(function=function)
        return item
    add("status", cmd_status)
    add("case-create", cmd_case_create, (("name",), {}), (("scope",), {"nargs":"?", "default":""}), (("authorization",), {"nargs":"?", "default":""}))
    add("case-select", cmd_case_select, (("ident",), {})); add("case-list", cmd_case_list); add("case-show", cmd_case_show); add("case-close", cmd_case_close)
    add("target-set", cmd_target_set, (("rat",), {}), (("plmn",), {}), (("channel",), {}), (("cell_id",), {}), (("area",), {"nargs":"?", "default":""}), (("pci",), {"nargs":"?", "default":""}), (("band",), {"nargs":"?", "default":""}), (("lat",), {"nargs":"?", "default":""}), (("lon",), {"nargs":"?", "default":""}), (("label",), {"nargs":"?", "default":""}))
    add("target-select", cmd_target_select, (("ident",), {})); add("target-clear", cmd_target_clear); p=add("targets", cmd_targets); p.set_defaults(current=False); p=add("target-current", cmd_targets); p.set_defaults(current=True)
    add("index", cmd_index); add("evidence-add", cmd_evidence_add, (("file",), {}), (("module",), {"nargs":"?", "default":""}), (("tags",), {"nargs":"?", "default":""}), (("sensitivity",), {"nargs":"?", "default":"sensitive"})); add("evidence", cmd_evidence, (("kind",), {"nargs":"?", "default":""})); add("captures", cmd_captures)
    add("timeline-add", cmd_timeline_add, (("severity",), {}), (("type",), {}), (("source",), {}), (("message",), {}), (("reference",), {"nargs":"?", "default":"-"})); add("timeline", cmd_timeline); add("correlate", cmd_correlate)
    add("alert-add", cmd_alert_add, (("severity",), {}), (("kind",), {}), (("source",), {}), (("message",), {}), (("evidence",), {"nargs":"?", "default":"-"})); add("alerts", cmd_alerts); add("alerts-clear", cmd_alerts_clear); add("baseline-build", cmd_baseline, (("file",), {"nargs":"?"})); add("ids-scan", cmd_ids_scan, (("file",), {}))
    add("observation-add", cmd_observation_add, (("node",), {}), (("target",), {}), (("rat",), {}), (("plmn",), {}), (("channel",), {}), (("cell_id",), {}), (("pci",), {}), (("signal",), {}), (("lat",), {"nargs":"?", "default":""}), (("lon",), {"nargs":"?", "default":""}), (("source",), {"nargs":"?", "default":"manual"})); add("observations", cmd_observations); add("observations-geojson", cmd_observations_geojson, (("file",), {"nargs":"?"}))
    add("node-add", cmd_node_add, (("name",), {}), (("host",), {}), (("transport",), {"nargs":"?", "choices":["ssh","local","adb"], "default":"ssh"}), (("role",), {"nargs":"?", "default":"sensor"})); add("node-remove", cmd_node_remove, (("name",), {})); add("nodes", cmd_nodes); add("node-probe", cmd_node_probe, (("name",), {})); add("node-collect", cmd_node_collect, (("name",), {}), (("remote_path",), {}))
    for name, function in (("report-html", cmd_report_html), ("report-json", cmd_report_json), ("report-tsv", cmd_report_tsv)):
        item = add(name, function, (("file",), {"nargs":"?"}))
        item.add_argument("--full", action="store_true", help="include unredacted subscriber identifiers")
    add("reports", cmd_reports)
    return parser


def run_selftest() -> int:
    global STATE, LOOT, CAPTURES, LOGS, CASES, BOOK, ACTIVE, NODES
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory); STATE=base/"state";LOOT=base/"loot";CAPTURES=base/"captures";LOGS=base/"logs";CASES=base/"cases";BOOK=STATE/"casebook";ACTIVE=BOOK/"active_case";NODES=BOOK/"nodes.tsv";init_root()
        failures = 0
        def check(name: str, actual: object, expected: object) -> None:
            nonlocal failures
            if actual == expected: print(f"PASS\t{name}")
            else: print(f"FAIL\t{name}\tgot={clean(actual)} want={clean(expected)}"); failures += 1
        cmd_case_create(argparse.Namespace(name="Lab Case",scope="owned lab",authorization="ticket-1")); check("case-id",active_id(),"lab-case")
        cmd_target_set(argparse.Namespace(rat="LTE",plmn="00101",channel="6300",cell_id="ABC",area="1",pci="42",band="B20",lat="1",lon="2",label="lab")); check("target",read_table(case_dir()/"targets.tsv",TARGET_FIELDS)[0]["selected"],"yes")
        (CAPTURES/"mod").mkdir(parents=True);(CAPTURES/"mod"/"a.pcap").write_bytes(b"pcap");cmd_index(argparse.Namespace());check("index",len(read_table(case_dir()/"evidence.tsv",EVIDENCE_FIELDS)),1)
        alert_add("HIGH","cell-change","test","changed","ref");check("alert",read_table(case_dir()/"alerts.tsv",ALERT_FIELDS)[0]["severity"],"HIGH")
        cmd_node_add(argparse.Namespace(name="localnode",host="localhost",transport="local",role="sensor"));cmd_node_probe(argparse.Namespace(name="localnode"));check("node",read_table(NODES,NODE_FIELDS)[0]["status"],"ONLINE")
        # A handset is a node with a transport and a role of its own. With no
        # adb on PATH the node is OFFLINE and says why -- it does not claim a
        # device it cannot see -- and it comes back ONLINE for a stub that
        # answers like a phone.
        cmd_node_add(argparse.Namespace(name="phone1",host="R58M12345",transport="adb",role="ue"))
        phone = next(row for row in read_table(NODES,NODE_FIELDS) if row["name"] == "phone1")
        check("node-adb-transport", phone["transport"], "adb")
        check("node-adb-role", phone["role"], "ue")
        check("node-adb-unseen", phone["status"], "UNKNOWN")
        saved_adb = os.environ.get("UE_ADB")
        try:
            os.environ["UE_ADB"] = "definitely-not-adb"
            try:
                cmd_node_probe(argparse.Namespace(name="phone1"))
                raised = False
            except SystemExit as exc:
                raised = exc.code == 1
            check("node-adb-offline-raises", raised, True)
            check("node-adb-offline-status",
                  next(row for row in read_table(NODES,NODE_FIELDS) if row["name"] == "phone1")["status"], "OFFLINE")
            check("node-adb-offline-detail",
                  next(row for row in read_table(NODES,NODE_FIELDS) if row["name"] == "phone1")["detail"], "state=absent")
        finally:
            if saved_adb is None:
                os.environ.pop("UE_ADB", None)
            else:
                os.environ["UE_ADB"] = saved_adb
        cmd_report_json(argparse.Namespace(file=None,full=False));cmd_report_html(argparse.Namespace(file=None,full=False));check("reports",len(list((case_dir()/"reports").iterdir())),2)
        check("sanitize",clean("a\tb\nc"),"a b c")
        print(f"RESULT\t{'PASS' if not failures else f'FAIL({failures})'}")
        return int(bool(failures))


def main() -> int:
    init_root()
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return run_selftest()
    aliases = {"--status-tsv":"status","--case-create":"case-create","--case-select":"case-select","--case-list-tsv":"case-list","--case-show-tsv":"case-show","--case-close":"case-close","--target-set":"target-set","--target-select":"target-select","--target-clear":"target-clear","--targets-tsv":"targets","--target-current-tsv":"target-current","--index":"index","--evidence-add":"evidence-add","--evidence-tsv":"evidence","--captures-tsv":"captures","--timeline-add":"timeline-add","--timeline-tsv":"timeline","--correlate":"correlate","--alert-add":"alert-add","--alerts-tsv":"alerts","--alerts-clear":"alerts-clear","--baseline-build":"baseline-build","--ids-scan":"ids-scan","--observation-add":"observation-add","--observations-tsv":"observations","--observations-geojson":"observations-geojson","--node-add":"node-add","--node-remove":"node-remove","--node-list-tsv":"nodes","--node-probe":"node-probe","--node-collect":"node-collect","--report-html":"report-html","--report-json":"report-json","--report-tsv":"report-tsv","--reports-tsv":"reports"}
    if len(sys.argv) > 1 and sys.argv[1] in aliases:
        sys.argv[1] = aliases[sys.argv[1]]
    args = build_parser().parse_args()
    args.function(args)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
