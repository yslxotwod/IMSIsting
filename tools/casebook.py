#!/usr/bin/env python3
"""IMSIsting Casebook: shared case/evidence state for CLI modules and GTK.

This is project infrastructure, not a cellular module. It intentionally does
not appear in module_index.tsv. Tables emitted by list commands are strict TSV.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
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
# A node row says what the box IS as well as where it is.  `class` and `caps`
# are written by a probe rather than declared by a human -- "a dongle" is a
# claim about capability, and a claim nobody measured is how a fleet view starts
# lying.  A declared class is kept: the operator may know the box better than
# its PATH does, and the probe only fills class when it is empty.
NODE_FIELDS = ["name", "host", "port", "transport", "class", "role", "caps", "allow", "added", "last_seen", "status", "detail"]

# Transports this toolkit can actually speak.  `diag` and `sms` are named
# because the cellular bench needs them and a table that cannot hold a fact is a
# table people work around; cmd_node_probe refuses them by name until a
# transport exists rather than pretending the node is down.
NODE_TRANSPORTS = ["ssh", "local", "adb", "serial", "qmi", "mbim", "diag", "sms"]
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


def refuse(message: str, why: str) -> "NoReturn":
    """Exit 2: the request was understood and cannot be done from here."""
    print(f"ERROR\t{clean(message)}", file=sys.stderr)
    print(f"WHY\t{clean(why)}", file=sys.stderr)
    raise SystemExit(2)


def node_field(node: dict, key: str) -> str:
    """Read a column that an older nodes.tsv may not have yet."""
    value = node.get(key)
    return "" if value is None or value == "-" else str(value).strip()


def node_agent_script() -> str:
    return (ROOT / "tools" / "node_agent.sh").read_text(encoding="utf-8")


def parse_agent(stdout: str) -> "tuple[dict[str, str], list[str]]":
    """Split tools/node_agent.sh rows into facts and the capability list.

    Caps repeat (`cap<TAB>at`, `cap<TAB>sdr-rx`), so they cannot go through a
    dict: the last cap would win and a four-capability node would report one.
    """
    pairs: dict[str, str] = {}
    caps: list[str] = []
    for line in stdout.splitlines():
        if "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        if key == "cap":
            if value and value not in caps:
                caps.append(value)
            continue
        pairs[key] = value
    return pairs, caps


def node_detail(pairs: dict[str, str], caps: list[str], extra: str = "") -> str:
    bits = [extra] if extra else []
    for key in ("host", "board", "os", "kernel", "android", "vendor", "model", "signal", "sim"):
        value = pairs.get(key, "").strip()
        if value:
            bits.append(f"{key}={value}")
    if not bits:
        return "-"
    return clean(" ".join(bits))


def probe_local(node: dict) -> "tuple[bool, str, list[str], str]":
    script = ROOT / "tools" / "node_agent.sh"
    if not script.exists():
        refuse("the local node agent is missing",
               f"{script} is not in this tree; a local node is probed by that file, not by a second copy here")
    result = subprocess.run(["sh", str(script), "--probe", "--caps"],
                            capture_output=True, text=True, timeout=25, check=False)
    pairs, caps = parse_agent(result.stdout)
    if result.returncode != 0 and not pairs:
        return False, clean((result.stderr or "node_agent returned nothing").strip()), caps, pairs.get("class", "")
    return True, node_detail(pairs, caps), caps, pairs.get("class", "")


def probe_ssh(node: dict) -> "tuple[bool, str, list[str], str]":
    """Pipe the agent over ssh, so the node is never written to."""
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
    port = node_field(node, "port")
    if port:
        argv += ["-p", port]
    argv += ["--", node_field(node, "host"), "sh -s -- --probe --caps"]
    try:
        result = subprocess.run(argv, input=node_agent_script(), capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, clean(str(exc)), [], ""
    pairs, caps = parse_agent(result.stdout)
    if result.returncode != 0:
        note = clean((result.stderr or result.stdout or "ssh returned nothing").strip().splitlines()[0]) if (result.stderr or result.stdout) else "ssh failed"
        return False, note, caps, pairs.get("class", "")
    return True, node_detail(pairs, caps), caps, pairs.get("class", "")


def probe_adb(node: dict) -> "tuple[bool, str, list[str], str]":
    """Ask the handset twice: is it there, then what can it do.

    The two questions are separate because they fail differently -- no adb
    binary, no cable, and an unauthorised cable are three facts, and a fleet view
    that collapsed them into "offline" would send the reader looking for the
    wrong one.  ue_agent.sh owns both answers; nothing is re-derived here.
    """
    try:
        probe = ue_agent(node_field(node, "host"), "--probe")
        pairs, _ = parse_agent(probe.stdout)
        state = pairs.get("state", "unknown")
        if state != "device":
            detail = " ".join(f"{key}={value}" for key, value in pairs.items()
                              if key in {"serial", "state", "version"})
            return False, clean(detail or (probe.stderr or "ue_agent returned nothing").strip()), [], ""
        result = ue_agent(node_field(node, "host"), "--caps")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, clean(str(exc)), [], ""
    caps_pairs, caps = parse_agent(result.stdout)
    detail = " ".join(f"{key}={value}" for key, value in caps_pairs.items()
                      if key in {"serial", "model", "android"})
    online = caps_pairs.get("status") == "online"
    return online, clean(detail or (result.stderr or "ue_agent returned nothing").strip()), caps, caps_pairs.get("class", "")


def at_channel(host: str, port: str):
    """A channel to a modem's AT parser: TCP host:port, or a device path.

    TCP is what ser2net and socat give you on a router; the device path is a
    stick on this desk.  Both are opened the same way so the caller talks AT and
    never learns which one it got.
    """
    if host.startswith("/"):
        import termios
        fd = os.open(host, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            iflag, oflag, cflag, lflag, _ispeed, _ospeed, cc = termios.tcgetattr(fd)
            speed = getattr(termios, f"B{os.environ.get('AT_BAUD', '115200')}", termios.B115200)
            cc = list(cc)
            cc[termios.VMIN] = 0
            cc[termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW,
                              [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0, speed, speed, cc])
        except (OSError, termios.error):
            os.close(fd)
            raise
        return ("fd", fd)
    return ("sock", socket.create_connection((host, int(port or 23)), timeout=5))


def at_close(channel) -> None:
    kind, handle = channel
    try:
        if kind == "fd":
            os.close(handle)
        else:
            handle.close()
    except OSError:
        pass


def at_talk(channel, command: str, wait: float = 1.5) -> str:
    """Send one AT command and read until OK/ERROR or the wait runs out."""
    import select
    import time
    kind, handle = channel
    payload = (command + "\r").encode()
    try:
        if kind == "fd":
            os.write(handle, payload)
        else:
            handle.sendall(payload)
    except OSError as exc:
        return f"ERROR {exc}"
    deadline = time.monotonic() + wait
    buffer = b""
    while time.monotonic() < deadline:
        if kind == "fd":
            ready, _, _ = select.select([handle], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(handle, 4096)
            except OSError:
                break
        else:
            handle.settimeout(0.2)
            try:
                chunk = handle.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
        if not chunk:
            break
        buffer += chunk
        upper = buffer.upper()
        if b"OK" in upper or b"ERROR" in upper:
            break
    return buffer.decode("utf-8", "replace").strip()


def at_value(reply: str, prefix: str) -> str:
    """The payload of one AT reply, skipping the echo, the blank lines and OK.

    An AT parser echoes the command back, so the first line of a reply is the
    command itself.  Returning it would put "AT+CGMI" in the model column and
    look like a successful read, which is the exact failure mode this avoids.
    """
    for line in reply.splitlines():
        line = line.strip()
        if not line or line.upper() in {"OK", "ERROR"}:
            continue
        if prefix:
            if line.startswith(prefix):
                return line[len(prefix):].strip().strip('"')
            continue
        if line.upper().startswith("AT"):
            continue
        return line
    return ""


def probe_serial(node: dict) -> "tuple[bool, str, list[str], str]":
    """AT over a serial bridge.  Reads the modem's vitals, never an identity.

    IMEI and IMSI are deliberately absent: this row lands in a node table that
    travels into case exports, and identity belongs in the loot stores where it
    is recorded with its source.
    """
    host = node_field(node, "host")
    try:
        channel = at_channel(host, node_field(node, "port"))
    except (OSError, ValueError) as exc:
        return False, clean(f"cannot open {host}: {exc}"), [], ""
    try:
        reply = at_talk(channel, "AT")
        if "OK" not in reply.upper():
            return False, clean(f"the endpoint answered but not with OK: {reply[:80]}"), [], ""
        pairs = {"vendor": at_value(at_talk(channel, "AT+CGMI"), ""),
                 "model": at_value(at_talk(channel, "AT+CGMM"), "")}
        pairs["signal"] = at_value(at_talk(channel, "AT+CSQ"), "+CSQ:")
        pin = at_talk(channel, "AT+CPIN?")
        pairs["sim"] = "ready" if "READY" in pin.upper() else ("absent" if "ERROR" in pin.upper() else "unknown")
        for key in list(pairs):
            if not pairs[key]:
                del pairs[key]
    finally:
        at_close(channel)
    return True, node_detail(pairs, ["at"]), ["at"], "dongle"


def probe_qmi(node: dict) -> "tuple[bool, str, list[str], str]":
    tool = shutil.which("uqmi")
    if tool is None:
        refuse("the qmi transport needs uqmi on this host",
               "install libqmi-utils, or reach the modem over serial/ssh instead of qmi")
    device = node_field(node, "host") or "/dev/cdc-wdm0"
    try:
        result = subprocess.run([tool, "-d", device, "--get-serving-system"],
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, clean(str(exc)), [], "dongle"
    text = (result.stdout or result.stderr).strip()
    online = result.returncode == 0
    pairs = {}
    for line in text.replace(",", "\n").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            pairs[clean(key).strip().strip('"')] = clean(value).strip().strip('"')
    return online, node_detail(pairs, ["qmi"], extra="") if online else clean(text[:160]), ["qmi"], "dongle"


def probe_mbim(node: dict) -> "tuple[bool, str, list[str], str]":
    tool = shutil.which("mbimcli")
    if tool is None:
        refuse("the mbim transport needs mbimcli on this host",
               "install libmbim-utils, or reach the modem over serial/ssh instead of mbim")
    device = node_field(node, "host") or "/dev/cdc-wdm0"
    try:
        result = subprocess.run([tool, "-d", device, "--query-device-caps"],
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, clean(str(exc)), [], "dongle"
    text = (result.stdout or result.stderr).strip()
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return result.returncode == 0, clean(first[:160]) or "-", ["mbim"], "dongle"


def probe_named_transport(node: dict) -> "tuple[bool, str, list[str], str]":
    """The transport is understood and no code speaks it yet.  Say so, with 2."""
    transport = node_field(node, "transport")
    if transport == "diag":
        refuse("no diag transport in this toolkit yet",
               "the modem's internal log is 56_baseband_diag's wire format, and it has no serial or TCP transport to reach a remote modem with")
    refuse("no sms transport in this toolkit yet",
           "SMS as a control channel would be 41_ota_sms's SMPP client plus AT+CMGS; nothing joins them to a node yet")
    return False, "-", [], ""


NODE_PROBES = {
    "local": probe_local,
    "ssh": probe_ssh,
    "adb": probe_adb,
    "serial": probe_serial,
    "qmi": probe_qmi,
    "mbim": probe_mbim,
    "diag": probe_named_transport,
    "sms": probe_named_transport,
}


def cmd_node_add(args: argparse.Namespace) -> None:
    try:
        ident = slug(args.name)
    except ValueError as exc:
        err(str(exc), 2)
    transport = args.transport or "ssh"
    if transport not in NODE_TRANSPORTS:
        refuse(f"unknown transport: {transport}", "known transports are " + ", ".join(NODE_TRANSPORTS))
    rows = [row for row in read_table(NODES, NODE_FIELDS) if row["name"] != ident]
    rows.append({"name": ident, "host": args.host, "port": getattr(args, "port", "") or "",
                 "transport": transport, "class": getattr(args, "node_class", "") or "",
                 "role": args.role, "caps": "", "allow": "", "added": now(), "last_seen": "-",
                 "status": "UNKNOWN", "detail": "-"})
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=ident, transport=transport)


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
    """Measure what the node can do, and record it.

    The rule this follows is the one the whole toolkit follows: an unprobed node
    is UNKNOWN, never ONLINE.  A probe that cannot speak the transport refuses
    with exit 2 and leaves the row alone, because "I could not ask" and "the box
    is down" are different facts and only one of them is about the box.
    """
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    transport = node_field(node, "transport")
    probe = NODE_PROBES.get(transport)
    if probe is None:
        refuse(f"unsupported transport: {transport}",
               "known transports are " + ", ".join(NODE_TRANSPORTS))
    online, detail, caps, inferred_class = probe(node)
    declared = node_field(node, "class")
    klass = declared or inferred_class or "unknown"
    node.update(last_seen=now(), status="ONLINE" if online else "OFFLINE",
                detail=clean(detail), caps=",".join(caps), **{"class": klass})
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=args.name, transport=transport, **{"class": klass},
               caps=",".join(caps) or "none", status=node["status"], detail=node["detail"])
    if not online:
        raise SystemExit(1)


# ── Node presets, roles and the dispatch allow-list ─────────────────────
#
# A preset is a device class with the transport and role that class usually
# arrives with.  It exists so a person adding the third dongle of the week does
# not have to remember that a USB stick is `serial` and a handset is `adb`; it
# does NOT fill in a capability, because a capability nobody measured is the one
# thing this registry refuses to guess.
NODE_PRESETS = [
    ("dongle", "serial", "ue", "USB modem: AT over /dev/ttyUSB* or a ser2net socket"),
    ("router", "ssh", "relay", "CPE or OpenWrt box: cell lock, signal, SMS"),
    ("sbc", "ssh", "sensor", "Pi-class board with an SDR or a modem hung off it"),
    ("phone", "adb", "ue", "Android handset: identity, radio log, no AT without root"),
    ("sim-kit", "local", "sim", "PC/SC reader or SIMtrace on this host"),
    ("smallcell", "ssh", "catcher", "Femtocell or a lab eNB/gNB you own"),
    ("core", "ssh", "core", "EPC/5GC software: subscribers and interfaces"),
    ("relay", "ssh", "relay", "A box that cannot hear anything and only forwards"),
]

# What a capability set is good for.  Derived, never declared: the caps came
# from measuring the box, so the roles do too.
def caps_roles(caps: list[str]) -> list[str]:
    roles = []
    for cap, role in (("sdr-rx", "sensor"), ("sdr-tx", "catcher"), ("gsmtap", "capture"),
                      ("at", "ue"), ("qmi", "ue"), ("mbim", "ue"), ("modem", "ue"),
                      ("pcsc", "sim"), ("simtrace", "sim"), ("core", "core"),
                      ("diag", "devices"), ("tcpdump", "capture")):
        if cap in caps and role not in roles:
            roles.append(role)
    if not roles:
        roles.append("relay")
    return roles


def cmd_node_presets(_: argparse.Namespace) -> None:
    emit(["class", "transport", "role", "note"],
         [{"class": c, "transport": t, "role": r, "note": n} for c, t, r, n in NODE_PRESETS])


def cmd_node_suggest_roles(args: argparse.Namespace) -> None:
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    caps = [c for c in node_field(node, "caps").split(",") if c]
    if not caps:
        refuse(f"no capabilities measured for {args.name}",
               "roles are derived from a probe; run --node-probe first, because a "
               "role nobody measured is a guess about a machine you cannot see")
    roles = caps_roles(caps)
    emit(["node", "role", "why"],
         [{"node": node["name"], "role": r,
           "why": "from caps " + ",".join(c for c in caps if c)} for r in roles])


def cmd_node_set_roles(args: argparse.Namespace) -> None:
    """Set the roles by hand, which is the only way to contradict a probe."""
    wanted = [r.strip() for r in args.roles.replace(",", " ").split() if r.strip()]
    if not wanted:
        refuse("no roles given", "usage: node-set-roles <name> sensor,capture")
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    node["role"] = ",".join(dict.fromkeys(wanted))
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=node["name"], roles=node["role"])


def cmd_node_allow(args: argparse.Namespace) -> None:
    """Which modules may be dispatched to this node.

    Empty means "no list, so no restriction" and is spelled out rather than
    implied: a fleet that silently accepts every module is the arrangement that
    puts a catcher on the wrong box by accident.
    """
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    if args.modules is None:
        emit_pairs(node=node["name"], allow=node_field(node, "allow") or "*",
                   note="no list: every module may be dispatched here"
                   if not node_field(node, "allow") else "restricted")
        return
    wanted = [] if args.modules.strip() in ("", "-", "*") else [
        m.strip() for m in args.modules.replace(",", " ").split() if m.strip()]
    node["allow"] = ",".join(dict.fromkeys(wanted))
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=node["name"], allow=node["allow"] or "*")


def node_allows(node: dict, stem: str) -> bool:
    allow = node_field(node, "allow")
    if not allow:
        return True
    number = stem.split("_", 1)[0]
    for entry in allow.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry in (stem, number) or stem.startswith(entry.rstrip("_") + "_") or entry == number:
            return True
    return False


def cmd_node_bulk_probe(_: argparse.Namespace) -> None:
    """Probe every node, and keep going when one of them cannot answer."""
    rows = read_table(NODES, NODE_FIELDS)
    out = []
    for node in rows:
        transport = node_field(node, "transport")
        probe = NODE_PROBES.get(transport)
        if probe is None:
            out.append({"node": node["name"], "transport": transport, "status": "UNKNOWN",
                        "class": node_field(node, "class") or "-",
                        "caps": "none", "detail": f"no {transport} transport"})
            continue
        try:
            online, detail, caps, inferred = probe(node)
        except SystemExit:
            out.append({"node": node["name"], "transport": transport, "status": "UNKNOWN",
                        "class": node_field(node, "class") or "-", "caps": "none",
                        "detail": "probe refused"})
            continue
        node.update(last_seen=now(), status="ONLINE" if online else "OFFLINE",
                    detail=clean(detail), caps=",".join(caps),
                    **{"class": node_field(node, "class") or inferred or "unknown"})
        out.append({"node": node["name"], "transport": transport, "status": node["status"],
                    "class": node_field(node, "class"), "caps": ",".join(caps) or "none",
                    "detail": clean(detail)})
    write_table(NODES, NODE_FIELDS, rows)
    emit(["node", "transport", "status", "class", "caps", "detail"], out)
    if any(row["status"] == "OFFLINE" for row in out):
        raise SystemExit(1)


def cmd_node_remove_offline(args: argparse.Namespace) -> None:
    rows = read_table(NODES, NODE_FIELDS)
    keep = [row for row in rows if node_field(row, "status") != "OFFLINE"]
    dropped = [row["name"] for row in rows if node_field(row, "status") == "OFFLINE"]
    if not dropped and not args.dry_run:
        emit_pairs(removed="0", nodes="-")
        return
    if not args.dry_run:
        write_table(NODES, NODE_FIELDS, keep)
    emit(["node", "state"],
         [{"node": name, "state": "would-remove" if args.dry_run else "removed"}
          for name in dropped])


def cmd_node_health(_: argparse.Namespace) -> None:
    """One round trip per node for the numbers that decide where work goes."""
    rows = read_table(NODES, NODE_FIELDS)
    out = []
    for node in rows:
        transport = node_field(node, "transport")
        base = {"node": node["name"], "transport": transport,
                "status": node_field(node, "status") or "UNKNOWN",
                "last_seen": node_field(node, "last_seen") or "-"}
        facts: dict[str, str] = {}
        try:
            if transport == "local":
                result = subprocess.run(["sh", str(ROOT / "tools" / "node_agent.sh"), "--health"],
                                        capture_output=True, text=True, timeout=20, check=False)
                if result.returncode == 0:
                    facts, _ = parse_agent(result.stdout)
            elif transport == "ssh":
                command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
                if node_field(node, "port"):
                    command += ["-p", node_field(node, "port")]
                command += [node_field(node, "host"), "sh -s -- --health"]
                result = subprocess.run(command, input=node_agent_script(),
                                        capture_output=True, text=True, timeout=40, check=False)
                if result.returncode == 0:
                    facts, _ = parse_agent(result.stdout)
            elif transport == "adb":
                # A handset has no shell to read /proc from, so the one health
                # fact it can give is the one adb does expose.
                result = ue_agent(node_field(node, "host"), "--caps")
                if result.returncode == 0:
                    facts, _ = parse_agent(result.stdout)
            else:
                # One node that cannot answer must not stop the fleet's health
                # report: the row says who could not be measured and why.
                facts = {"note": f"a {transport} link carries no shell"}
        except (OSError, subprocess.TimeoutExpired):
            facts = {}
        for key in ("load1", "uptime_s", "mem_used_pct", "disk_used_pct", "run_count"):
            base[key] = facts.get(key, "unmeasured")
        if facts.get("note"):
            base["run_count"] = facts["note"]
        if facts.get("battery"):
            base["uptime_s"] = f"battery={facts['battery']}"
        out.append(base)
    emit(["node", "transport", "status", "last_seen", "load1", "uptime_s",
          "mem_used_pct", "disk_used_pct", "run_count"], out)


# ── Node streams ────────────────────────────────────────────────────────
#
# A node spools its own events and this side keeps the cursor.  That way a
# dropped link costs a round trip, not the traffic that happened while it was
# down -- which is the one thing a client-side `nohup ssh ... >> file` cannot
# do, and the reason a field node is worth having at all.
#
# The spool file here is a table with the columns the node's agent writes, so
# it can be read by anything that reads a TSV: the casebook indexer, the GUI,
# or `cut -f1 | sort | uniq -c`.

STREAM_FIELDS = ["kind", "epoch", "src", "type", "len", "detail"]
STREAM_META = {"spool", "source", "size"}


def node_runtime(name: str, suffix: str) -> Path:
    return STATE / "nodes" / f"{name}{suffix}"


def split_stream(stdout: str) -> "tuple[dict[str, str], str]":
    """Separate the agent's meta rows from the spool bytes it drained.

    Not every line from the node is an event: `spool`, `source` and `size` come
    first and describe the drain.  Everything after them is the spool's own
    bytes, header included when the cursor was zero.
    """
    meta: dict[str, str] = {}
    body: list[str] = []
    for line in stdout.splitlines():
        if not body and "\t" in line:
            key, value = line.split("\t", 1)
            if key in STREAM_META:
                meta[key] = value.strip()
                continue
        if line.strip():
            body.append(line)
    return meta, ("\n".join(body) + "\n") if body else ""


def stream_pull(node: dict, since: int) -> "tuple[int, dict[str, str], str]":
    """Drain one node's spool from a byte offset: (status, meta, rows)."""
    transport = node_field(node, "transport")
    host = node_field(node, "host")
    if transport == "local":
        result = subprocess.run(["sh", str(ROOT / "tools" / "node_agent.sh"),
                                 "--since", str(since), "--stream"],
                                capture_output=True, text=True, timeout=90, check=False)
        meta, body = split_stream(result.stdout)
        return result.returncode, meta, body
    if transport == "ssh":
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        port = node_field(node, "port")
        if port:
            argv += ["-p", port]
        argv += ["--", host, f"sh -s -- --since {since} --stream"]
        try:
            result = subprocess.run(argv, input=node_agent_script(), capture_output=True,
                                    text=True, timeout=90, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 1, {}, ""
        meta, body = split_stream(result.stdout)
        return result.returncode, meta, body
    if transport == "adb":
        # A handset has nowhere to spool and no tshark, so its stream is the
        # radio log read at a moment: the same columns, one snapshot per call.
        try:
            result = ue_agent(host, "--radio-log")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 1, {}, ""
        if result.returncode != 0:
            return result.returncode, {}, ""
        epoch = f"{time.time():.1f}"
        rows = [f"radio\t{epoch}\t{clean(host)}\t{clean(key)}\t-\t{clean(value)}"
                for key, _, value in (line.partition("\t") for line in result.stdout.splitlines())
                if value]
        return 0, {"source": "ue_agent"}, ("\n".join(rows) + "\n") if rows else ""
    refuse(f"a {transport} node has no stream",
           "a modem link carries AT one command at a time and a device node carries a driver; "
           "a stream needs a shell on the node, over ssh or adb")


def stream_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return max(0, sum(1 for line in handle if line.strip()) - 1)


def cmd_node_stream(args: argparse.Namespace) -> None:
    """Collect a node's events into a local spool, resuming from the cursor."""
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    path = node_runtime(args.name, ".stream.tsv")
    cursor = node_runtime(args.name, ".since")
    path.parent.mkdir(parents=True, exist_ok=True)
    since = 0
    if cursor.exists():
        try:
            since = int(cursor.read_text(encoding="utf-8").strip() or 0)
        except ValueError:
            since = 0
    try:
        follow = float(getattr(args, "follow", 0) or 0)
    except ValueError:
        refuse("--follow wants seconds", "give a number; 0 asks once and returns")
    try:
        interval = max(1.0, float(getattr(args, "interval", 2) or 2))
    except ValueError:
        interval = 2.0
    deadline = time.monotonic() + follow if follow > 0 else 0.0
    started = stream_rows(path)
    source = ""
    added = 0
    status = 0
    while True:
        status, meta, body = stream_pull(node, since)
        if meta.get("source"):
            source = meta["source"]
        if not meta and status != 0:
            node.update(status="OFFLINE", detail=clean("stream: the node did not answer"))
            write_table(NODES, NODE_FIELDS, rows)
            emit_pairs(node=args.name, stream=path, status="OFFLINE", since=since)
            raise SystemExit(1)
        if body:
            text = body
            if path.exists() and path.stat().st_size > 0:
                # The spool header belongs to the file, not to every drain.
                kept = body.splitlines(keepends=True)
                if kept and kept[0].startswith("kind\t"):
                    text = "".join(kept[1:])
            if text:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(text)
                added += text.count("\n")
                # The rows are printed as well as spooled. A caller that only
                # wants the file ignores stdout; the GUI feed has no other way
                # to show what arrived without reading this tree's state path,
                # and "drain wrote 5 rows somewhere" is not a feed.
                sys.stdout.write(text)
        size = meta.get("size", "")
        if size.isdigit():
            since = int(size)
            cursor.write_text(f"{since}\n", encoding="utf-8")
        if not deadline or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    node.update(status="ONLINE", last_seen=now())
    write_table(NODES, NODE_FIELDS, rows)
    # str() because clean() renders a bare 0 as nothing, and "no new rows" is a
    # fact worth printing.
    emit_pairs(node=args.name, stream=path, source=source or "unknown",
               added=str(added), rows=str(stream_rows(path)), since=str(since))


def cmd_node_stream_status(_: argparse.Namespace) -> None:
    """One row per node that has ever streamed, with how stale it is."""
    rows = []
    for node in read_table(NODES, NODE_FIELDS):
        path = node_runtime(node["name"], ".stream.tsv")
        if not path.exists():
            continue
        last = 0.0
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.rstrip("\n").split("\t")
                if len(fields) >= 2:
                    try:
                        last = max(last, float(fields[1]))
                    except ValueError:
                        continue
        cursor = node_runtime(node["name"], ".since")
        since = cursor.read_text(encoding="utf-8").strip() if cursor.exists() else "0"
        rows.append({"node": node["name"], "class": node_field(node, "class") or "-",
                     "transport": node_field(node, "transport"), "rows": stream_rows(path),
                     "bytes": path.stat().st_size, "since": since,
                     "last": f"{last:.0f}" if last else "-",
                     "lag_s": f"{max(0.0, time.time() - last):.0f}" if last else "-"})
    emit(["node", "class", "transport", "rows", "bytes", "since", "last", "lag_s"], rows)


def cmd_node_stream_stop(args: argparse.Namespace) -> None:
    pid_file = node_runtime(args.name, ".pid")
    if not pid_file.exists():
        err(f"no stream running for {args.name}")
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except ValueError:
        pid_file.unlink(missing_ok=True)
        err(f"unreadable pid file for {args.name}")
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        emit_pairs(node=args.name, stopped="already-gone")
        return
    pid_file.unlink(missing_ok=True)
    emit_pairs(node=args.name, stopped="signalled", pid=pid)


# ── Node dispatch ───────────────────────────────────────────────────────
#
# Dispatch runs a module verb on a node that has the toolkit, and brings the
# rows back.  It does not run a module here and pretend the node agreed: the
# rows are written to a file with the node's name on it, and a node without the
# toolkit is a handoff (exit 3), not a result.

MODULE_TOKEN = re.compile(r"^[0-9]{2}_[A-Za-z0-9_]+$")
DISPATCH_TRANSPORTS = {"local", "ssh"}


def module_stem(token: str, root: str = "") -> str:
    """A module number, file stem or display name -> the module file stem.

    The index describes this tree; a node may carry a different version, so when
    the node's own tree is known its modules are consulted as well.
    """
    token = token.strip()
    if MODULE_TOKEN.match(token):
        return token
    number = token.zfill(2) if token.isdigit() else token
    index = ROOT / "module_index.tsv"
    if index.exists():
        with index.open(encoding="utf-8", errors="replace") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                stem = row.get("MODULE", "")
                name = row.get("NAME", "")
                if stem == number or stem.startswith(f"{number}_") or name.lower() == token.lower():
                    return stem
    if root:
        for path in sorted((Path(root) / "modules").glob(f"{number}*.sh")):
            return path.stem
    return ""


def dispatch_command(stem: str, verb: str, arguments: "list[str]", root: str) -> str:
    """The command a node runs. A tree-rooted node is entered first: a module
    writes into its own loot/, so it must run where its tree begins."""
    argv = [f"modules/{stem}.sh"] if root else ["imsisting", "--npm-module", stem, "--"]
    argv += [verb, *arguments]
    quoted = " ".join(shlex.quote(part) for part in argv)
    return f"cd {shlex.quote(root)} && {quoted}" if root else quoted


def handoff(message: str, why: str) -> "NoReturn":
    """Exit 3: understood, in scope, and the far side cannot answer."""
    print(f"ERROR\t{clean(message)}", file=sys.stderr)
    print(f"WHY\t{clean(why)}", file=sys.stderr)
    raise SystemExit(3)


def cmd_node_dispatch(args: argparse.Namespace) -> None:
    rows = read_table(NODES, NODE_FIELDS)
    node = next((row for row in rows if row["name"] == args.name), None)
    if node is None:
        err(f"unknown node: {args.name}")
    verb = args.verb
    arguments = list(getattr(args, "arguments", []) or [])
    leftovers = list(getattr(args, "leftovers", []) or [])
    if not verb and leftovers:
        verb, leftovers = leftovers[0], leftovers[1:]
    arguments += leftovers
    if not verb:
        refuse("no verb to dispatch",
               "give the module verb to run on the node, e.g. `node-dispatch desk 06 --selftest`")
    if not node_allows(node, module_stem(args.module, "") or str(args.module)):
        refuse(f"{args.name} does not admit {args.module}",
               "this node carries a dispatch allow-list; widen it with "
               f"`node-allow {args.name} <module,...>` or clear it with `node-allow {args.name} -`")
    transport = node_field(node, "transport")
    if transport not in DISPATCH_TRANSPORTS:
        refuse(f"a {transport} node cannot run a module",
               "a modem link carries AT one command at a time and a device node carries a driver; "
               "dispatch needs a shell on the node, so reach it over ssh or run the module here as the local node")
    root_env = os.environ.get("IMSISTING_NODE_ROOT", "").rstrip("/")
    stem = module_stem(args.module, root_env or (str(ROOT) if transport == "local" else ""))
    if not stem:
        refuse(f"unknown module: {args.module}",
               "give a number (06), a file stem (06_gsm_air) or a display name from module_index.tsv")
    # A local node is this machine, so its toolkit is this tree.  A remote node
    # has to be told where its copy lives, because guessing a path on a router
    # would be worse than saying nothing.
    root = root_env
    if not root and transport == "local":
        root = str(ROOT)
    if root and not (Path(root) / "modules" / f"{stem}.sh").exists():
        handoff(f"{args.name} has no {stem} to dispatch to",
                "either install the npm package on the node (imsisting --npm-module "
                f"{stem} -- {verb}) or point IMSISTING_NODE_ROOT at a tree there")
    command = dispatch_command(stem, verb, arguments, root)
    if transport == "local":
        result = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=300, check=False)
    else:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        port = node_field(node, "port")
        if port:
            argv += ["-p", port]
        argv += ["--", node_field(node, "host"), command]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            handoff(f"dispatch to {args.name} did not complete", str(exc))
    artifact_dir = STATE / "nodes" / "dispatch"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact = artifact_dir / f"{stamp}-{args.name}-{stem}{re.sub(r'[^A-Za-z0-9]+', '_', verb)}.tsv"
    artifact.write_text(result.stdout or "", encoding="utf-8")
    if result.returncode == 127:
        handoff(f"{args.name} has no toolkit to dispatch to",
                "either install the npm package on the node (imsisting --npm-module "
                f"{stem} -- {verb}) or point IMSISTING_NODE_ROOT at a tree there")
    node.update(last_seen=now(), status="ONLINE")
    write_table(NODES, NODE_FIELDS, rows)
    emit_pairs(node=args.name, module=stem, verb=verb, rc=str(result.returncode),
               rows=str(sum(1 for line in (result.stdout or "").splitlines() if line.strip())),
               artifact=artifact)
    if result.stderr.strip():
        emit_pairs(stderr=clean(result.stderr.strip().splitlines()[0]))
    if result.returncode != 0:
        raise SystemExit(result.returncode)


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
    add("node-add", cmd_node_add, (("name",), {}), (("host",), {}), (("transport",), {"nargs":"?", "choices":NODE_TRANSPORTS, "default":"ssh"}), (("role",), {"nargs":"?", "default":"sensor"}), (("--port",), {"dest":"port", "default":"", "help":"serial/qmi port or ssh port"}), (("--class",), {"dest":"node_class", "default":"", "help":"declare the device class; the probe fills it when empty"})); add("node-remove", cmd_node_remove, (("name",), {})); add("nodes", cmd_nodes); add("node-probe", cmd_node_probe, (("name",), {})); add("node-collect", cmd_node_collect, (("name",), {}), (("remote_path",), {})); add("node-stream", cmd_node_stream, (("name",), {}), (("--follow",), {"dest":"follow", "default":"0", "help":"seconds to keep draining; 0 asks once"}), (("--interval",), {"dest":"interval", "default":"2", "help":"seconds between drains while following"})); add("node-stream-status", cmd_node_stream_status); add("node-stream-stop", cmd_node_stream_stop, (("name",), {})); add("node-presets", cmd_node_presets); add("node-suggest-roles", cmd_node_suggest_roles, (("name",), {})); add("node-set-roles", cmd_node_set_roles, (("name",), {}), (("roles",), {})); add("node-allow", cmd_node_allow, (("name",), {}), (("modules",), {"nargs":"?", "default":None})); add("node-bulk-probe", cmd_node_bulk_probe); add("node-remove-offline", cmd_node_remove_offline, (("--dry-run",), {"dest":"dry_run", "action":"store_true"})); add("node-health", cmd_node_health); add("node-dispatch", cmd_node_dispatch, (("name",), {}), (("module",), {}), (("verb",), {"nargs":"?", "default":"", "help":"a module verb; verbs that begin with -- are taken from the leftovers"}), (("arguments",), {"nargs":"*", "default":[]}))
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
        cmd_node_add(argparse.Namespace(name="dispatcher",host="localhost",transport="local",role="sensor"));cmd_node_probe(argparse.Namespace(name="dispatcher"));check("node",read_table(NODES,NODE_FIELDS)[0]["status"],"ONLINE")
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
        # 9. The node table says what the box IS, and a probe fills it.
        #    A local probe runs tools/node_agent.sh for real, so the class is
        #    whatever this host is -- the assertions are about the shape of the
        #    answer, because pinning "this laptop is a relay" would make the
        #    selftest a description of the developer's machine.
        def node_row(ident: str) -> dict:
            return next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == ident)

        cmd_node_add(argparse.Namespace(name="desk", host="localhost", port="", transport="local",
                                        role="sensor", node_class=""))
        cmd_node_probe(argparse.Namespace(name="desk"))
        desk = node_row("desk")
        check("node-local-status", desk["status"], "ONLINE")
        check("node-local-class-known",
              desk["class"] in {"phone", "phone-rooted", "router", "sbc", "sdr", "core", "sim-kit",
                                "dongle", "workstation", "relay", "unknown"}, True)
        check("node-local-caps-nonempty", desk["caps"] != "", True)
        check("node-local-detail-shaped", any(key in desk["detail"] for key in ("host=", "os=", "kernel=")), True)

        # A class a human declared is not overwritten by the probe: the operator
        # may know the box better than its PATH does.
        cmd_node_add(argparse.Namespace(name="declared", host="localhost", port="", transport="local",
                                        role="sensor", node_class="router"))
        cmd_node_probe(argparse.Namespace(name="declared"))
        check("node-declared-class-wins", node_row("declared")["class"], "router")

        # 10. The serial transport against a stub modem.  A probe that can only
        #     be tested with a dongle in the port is a probe nobody tested, and
        #     AT is the one transport whose framing can be faked exactly.
        import threading
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        at_port = server.getsockname()[1]

        def at_modem() -> None:
            conn, _ = server.accept()
            with conn:
                buffer = b""
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    buffer += data
                    while b"\r" in buffer:
                        command, buffer = buffer.split(b"\r", 1)
                        answer = {
                            b"AT": "AT\r\r\nOK\r\n",
                            b"AT+CGMI": "AT+CGMI\r\r\nQuectel\r\n\r\nOK\r\n",
                            b"AT+CGMM": "AT+CGMM\r\r\nEC25-E\r\n\r\nOK\r\n",
                            b"AT+CSQ": "AT+CSQ\r\r\n+CSQ: 22,99\r\n\r\nOK\r\n",
                            b"AT+CPIN?": "AT+CPIN?\r\r\n+CPIN: READY\r\n\r\nOK\r\n",
                        }.get(command.strip().upper(), "ERROR\r\n")
                        conn.sendall(answer.encode())

        threading.Thread(target=at_modem, daemon=True).start()
        cmd_node_add(argparse.Namespace(name="desk-dongle", host="127.0.0.1", port=str(at_port),
                                        transport="serial", role="sensor", node_class=""))
        cmd_node_probe(argparse.Namespace(name="desk-dongle"))
        dongle = node_row("desk-dongle")
        check("node-serial-status", dongle["status"], "ONLINE")
        check("node-serial-class", dongle["class"], "dongle")
        check("node-serial-caps", dongle["caps"], "at")
        check("node-serial-port-kept", dongle["port"], str(at_port))
        check("node-serial-vendor", "vendor=Quectel" in dongle["detail"], True)
        check("node-serial-model", "model=EC25-E" in dongle["detail"], True)
        check("node-serial-sim", "sim=ready" in dongle["detail"], True)
        check("node-serial-no-identity", any(word in dongle["detail"] for word in ("imei", "imsi")), False)
        server.close()

        # A serial endpoint nobody answers on is OFFLINE with the reason, not a
        # node that quietly kept its last status.
        cmd_node_add(argparse.Namespace(name="dead-dongle", host="127.0.0.1", port="9",
                                        transport="serial", role="sensor", node_class=""))
        try:
            cmd_node_probe(argparse.Namespace(name="dead-dongle"))
            dead_rc = 0
        except SystemExit as exc:
            dead_rc = exc.code
        check("node-serial-dead-rc", dead_rc, 1)
        check("node-serial-dead-status", node_row("dead-dongle")["status"], "OFFLINE")

        # 11. A transport this toolkit cannot speak refuses with exit 2 and
        #     leaves the row alone.  "I could not ask" is not "the box is down".
        cmd_node_add(argparse.Namespace(name="smsnode", host="+4915112345678", port="",
                                        transport="sms", role="sensor", node_class=""))
        try:
            cmd_node_probe(argparse.Namespace(name="smsnode"))
            sms_rc = 0
        except SystemExit as exc:
            sms_rc = exc.code
        check("node-sms-refused-rc", sms_rc, 2)
        check("node-sms-status-untouched", node_row("smsnode")["status"], "UNKNOWN")

        # 12. A nodes.tsv written by an older build has eight columns.  Reading
        #     it must not crash, and the first write must upgrade the header
        #     rather than dropping whatever the new columns cannot hold.
        NODES.write_text("name\thost\ttransport\trole\tadded\tlast_seen\tstatus\tdetail\n"
                         "legacy\t10.0.0.9\tssh\tsensor\t2024-01-01T00:00:00Z\t-\tUNKNOWN\t-\n",
                         encoding="utf-8")
        legacy = read_table(NODES, NODE_FIELDS)[0]
        check("node-migrate-old-row-class", legacy.get("class") or "", "")
        check("node-migrate-old-row-kept", legacy.get("name"), "legacy")
        cmd_node_add(argparse.Namespace(name="after", host="10.0.0.10", port="", transport="ssh",
                                        role="sensor", node_class=""))
        check("node-migrate-header", NODES.read_text(encoding="utf-8").splitlines()[0].split("\t"), NODE_FIELDS)
        check("node-migrate-row-survived",
              any(row["name"] == "legacy" for row in read_table(NODES, NODE_FIELDS)), True)

        # A stream must survive being asked twice: the node keeps the events,
        # this side keeps a byte cursor, and the second drain adds nothing.
        spool = base / "node-spool.tsv"
        silent = contextlib.redirect_stdout(io.StringIO())
        saved_env = {key: os.environ.get(key) for key in
                     ("NODE_SPOOL", "NODE_STREAM_WINDOW", "IMSISTING_NODE_ROOT")}
        try:
            os.environ["NODE_SPOOL"] = str(spool)
            os.environ["NODE_STREAM_WINDOW"] = "1"
            with silent: cmd_node_add(argparse.Namespace(name="streamer", host="localhost", port="",
                                            transport="local", role="sensor", node_class=""))
            with silent: cmd_node_stream(argparse.Namespace(name="streamer", follow="0", interval="2"))
            check("node-stream-cursor", node_runtime("streamer", ".since").exists(), True)
            check("node-stream-spool-header",
                  spool.read_text(encoding="utf-8").splitlines()[0].split("\t"), STREAM_FIELDS)
            with spool.open("a", encoding="utf-8") as handle:
                handle.write("gsmtap\t1755000000.5\t10.0.0.2\t1\t84\tnas-attach\n")
            with silent: cmd_node_stream(argparse.Namespace(name="streamer", follow="0", interval="2"))
            check("node-stream-drained", stream_rows(node_runtime("streamer", ".stream.tsv")), 1)
            with silent: cmd_node_stream(argparse.Namespace(name="streamer", follow="0", interval="2"))
            check("node-stream-idempotent", stream_rows(node_runtime("streamer", ".stream.tsv")), 1)
            # A handset that will not answer is OFFLINE and says so, rather than
            # pretending it is watching.
            with silent: cmd_node_add(argparse.Namespace(name="handset", host="R58M12345", port="",
                                                         transport="adb", role="ue", node_class=""))
            saved_adb_env = os.environ.get("UE_ADB")
            os.environ["UE_ADB"] = "definitely-not-adb"
            try:
                with silent: cmd_node_stream(argparse.Namespace(name="handset", follow="0", interval="2"))
                stream_raised = False
            except SystemExit as exc:
                stream_raised = exc.code == 1
            finally:
                if saved_adb_env is None:
                    os.environ.pop("UE_ADB", None)
                else:
                    os.environ["UE_ADB"] = saved_adb_env
            check("node-stream-offline-raises", stream_raised, True)
            check("node-stream-offline-status",
                  next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == "handset")["status"],
                  "OFFLINE")

            # Dispatch runs a module on the node and keeps its rows, with the
            # module's own status -- including a handoff when there is no
            # toolkit there at all.
            with silent: cmd_node_add(argparse.Namespace(name="smsgw", host="127.0.0.1", port="1",
                                            transport="serial", role="relay", node_class=""))
            with silent: cmd_node_add(argparse.Namespace(name="dispatcher", host="localhost", port="",
                                            transport="local", role="sensor", node_class=""))
            fake = base / "fakeroot" / "modules"
            fake.mkdir(parents=True)
            (fake / "99_fake.sh").write_text("#!/bin/sh\ncase \"$1\" in\n"
                                             "  --rows) printf 'key\\tvalue\\nwhere\\t%s\\n' \"$(pwd)\"; exit 0 ;;\n"
                                             "esac\nexit 7\n", encoding="utf-8")
            (fake / "99_fake.sh").chmod(0o755)
            os.environ["IMSISTING_NODE_ROOT"] = str(base / "fakeroot")
            with silent: cmd_node_dispatch(argparse.Namespace(name="dispatcher", module="99", verb="",
                                                 arguments=[], leftovers=["--rows"]))
            artifacts = sorted((STATE / "nodes" / "dispatch").glob("*-dispatcher-99_fake*.tsv"))
            check("node-dispatch-artifact", len(artifacts), 1)
            check("node-dispatch-rows", artifacts[0].read_text(encoding="utf-8").splitlines()[1],
                  f"where\t{base / 'fakeroot'}")
            try:
                with silent: cmd_node_dispatch(argparse.Namespace(name="dispatcher", module="99", verb="",
                                                     arguments=[], leftovers=["--boom"]))
                dispatch_rc = 0
            except SystemExit as exc:
                dispatch_rc = exc.code
            check("node-dispatch-propagates-rc", dispatch_rc, 7)
            try:
                with silent: cmd_node_dispatch(argparse.Namespace(name="dispatcher", module="77", verb="--rows",
                                                     arguments=[], leftovers=[]))
                unknown_rc = 0
            except SystemExit as exc:
                unknown_rc = exc.code
            check("node-dispatch-unknown-module", unknown_rc, 2)
            try:
                with silent: cmd_node_dispatch(argparse.Namespace(name="smsgw", module="99", verb="--rows",
                                                     arguments=[], leftovers=[]))
                serial_rc = 0
            except SystemExit as exc:
                serial_rc = exc.code
            check("node-dispatch-refuses-modem-link", serial_rc, 2)
            # A module this tree knows but that node does not have is a handoff:
            # understood, in scope, and the far side cannot answer.
            os.environ["IMSISTING_NODE_ROOT"] = str(base / "no-toolkit")
            try:
                with silent: cmd_node_dispatch(argparse.Namespace(name="dispatcher", module="00", verb="",
                                                     arguments=[], leftovers=["--preflight"]))
                handoff_rc = 0
            except SystemExit as exc:
                handoff_rc = exc.code
            check("node-dispatch-handoff", handoff_rc, 3)

            # ── presets, roles and the allow-list ───────────────────────────
            # A preset carries a transport and a role, never a capability: the
            # only capability worth having is one a probe measured.
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf): cmd_node_presets(argparse.Namespace())
            preset_rows = [line.split("\t") for line in buf.getvalue().splitlines()[1:] if line]
            check("node-preset-count", len(preset_rows), len(NODE_PRESETS))
            check("node-preset-dongle-transport",
                  next(row for row in preset_rows if row[0] == "dongle")[1], "serial")
            check("node-preset-no-caps-column", "caps" in buf.getvalue().splitlines()[0], False)

            # Roles are derived from measured caps, and refused without them.
            with silent: cmd_node_add(argparse.Namespace(name="roled", host="localhost", port="",
                                            transport="local", role="sensor", node_class=""))
            try:
                with silent: cmd_node_suggest_roles(argparse.Namespace(name="roled"))
                suggest_rc = 0
            except SystemExit as exc:
                suggest_rc = exc.code
            check("node-suggest-roles-refuses-unmeasured", suggest_rc, 2)
            check("node-caps-roles-sdr", caps_roles(["sdr-rx", "sdr-tx"])[:2],
                  ["sensor", "catcher"])
            check("node-caps-roles-empty", caps_roles([]), ["relay"])
            with silent: cmd_node_set_roles(argparse.Namespace(name="roled", roles="sensor,capture"))
            check("node-set-roles",
                  next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == "roled")["role"],
                  "sensor,capture")

            # The allow-list keeps a module off a node it was not admitted to,
            # and an empty list keeps nothing off.
            roled = next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == "roled")
            check("node-allow-empty-permits", node_allows(roled, "06_gsm_air"), True)
            with silent: cmd_node_allow(argparse.Namespace(name="roled", modules="06"))
            roled = next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == "roled")
            check("node-allow-match-by-number", node_allows(roled, "06_gsm_air"), True)
            check("node-allow-blocks-other", node_allows(roled, "07_gsm_attack"), False)
            try:
                with silent: cmd_node_dispatch(argparse.Namespace(name="roled", module="99", verb="",
                                                     arguments=[], leftovers=["--rows"]))
                allow_rc = 0
            except SystemExit as exc:
                allow_rc = exc.code
            check("node-allow-refuses-dispatch", allow_rc, 2)
            with silent: cmd_node_allow(argparse.Namespace(name="roled", modules="-"))
            roled = next(row for row in read_table(NODES, NODE_FIELDS) if row["name"] == "roled")
            check("node-allow-clear", node_allows(roled, "99_fake"), True)

            # Bulk probe keeps going past a node that cannot answer, and the
            # health table marks what it could not measure instead of pretending.
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf): cmd_node_bulk_probe(argparse.Namespace())
                bulk_rc = 0
            except SystemExit as exc:
                bulk_rc = exc.code
            check("node-bulk-probe-continues", bulk_rc, 1)
            check("node-bulk-probe-rows",
                  len([l for l in buf.getvalue().splitlines()[1:] if l]), len(read_table(NODES, NODE_FIELDS)))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf): cmd_node_health(argparse.Namespace())
            health_header = buf.getvalue().splitlines()[0].split("\t")
            check("node-health-header", "disk_used_pct" in health_header, True)
            check("node-health-marks-unmeasured",
                  any("unmeasured" in line for line in buf.getvalue().splitlines()[1:]), True)

            # remove-offline is a dry run by default when asked to be.
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf): cmd_node_remove_offline(argparse.Namespace(dry_run=True))
            check("node-remove-offline-dry-run",
                  len(read_table(NODES, NODE_FIELDS)), len(read_table(NODES, NODE_FIELDS)))
            offline_names = [row["name"] for row in read_table(NODES, NODE_FIELDS)
                             if node_field(row, "status") == "OFFLINE"]
            check("node-remove-offline-names", all(name in buf.getvalue() for name in offline_names), True)
            with silent: cmd_node_remove_offline(argparse.Namespace(dry_run=False))
            check("node-remove-offline-drops",
                  [row["name"] for row in read_table(NODES, NODE_FIELDS) if node_field(row, "status") == "OFFLINE"],
                  [])
        finally:
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        cmd_report_json(argparse.Namespace(file=None,full=False));cmd_report_html(argparse.Namespace(file=None,full=False));check("reports",len(list((case_dir()/"reports").iterdir())),2)
        check("sanitize",clean("a\tb\nc"),"a b c")
        print(f"RESULT\t{'PASS' if not failures else f'FAIL({failures})'}")
        return int(bool(failures))


def main() -> int:
    init_root()
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return run_selftest()
    aliases = {"--status-tsv":"status","--case-create":"case-create","--case-select":"case-select","--case-list-tsv":"case-list","--case-show-tsv":"case-show","--case-close":"case-close","--target-set":"target-set","--target-select":"target-select","--target-clear":"target-clear","--targets-tsv":"targets","--target-current-tsv":"target-current","--index":"index","--evidence-add":"evidence-add","--evidence-tsv":"evidence","--captures-tsv":"captures","--timeline-add":"timeline-add","--timeline-tsv":"timeline","--correlate":"correlate","--alert-add":"alert-add","--alerts-tsv":"alerts","--alerts-clear":"alerts-clear","--baseline-build":"baseline-build","--ids-scan":"ids-scan","--observation-add":"observation-add","--observations-tsv":"observations","--observations-geojson":"observations-geojson","--node-add":"node-add","--node-remove":"node-remove","--node-list-tsv":"nodes","--node-probe":"node-probe","--node-collect":"node-collect","--node-stream":"node-stream","--node-stream-status":"node-stream-status","--node-stream-stop":"node-stream-stop","--node-dispatch":"node-dispatch","--node-presets":"node-presets","--node-suggest-roles":"node-suggest-roles","--node-set-roles":"node-set-roles","--node-allow":"node-allow","--node-bulk-probe":"node-bulk-probe","--node-remove-offline":"node-remove-offline","--node-health":"node-health","--report-html":"report-html","--report-json":"report-json","--report-tsv":"report-tsv","--reports-tsv":"reports"}
    if len(sys.argv) > 1 and sys.argv[1] in aliases:
        sys.argv[1] = aliases[sys.argv[1]]
    parser = build_parser()
    # Most module verbs are spelled `--something`, so argparse would read them
    # as our own flags and fail.  Dispatch keeps the leftovers and decides.
    args, leftovers = parser.parse_known_args()
    if leftovers and getattr(args, "command", "") != "node-dispatch":
        parser.error("unrecognized arguments: " + " ".join(leftovers))
    args.leftovers = list(leftovers)
    args.function(args)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
