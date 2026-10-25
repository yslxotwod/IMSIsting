#!/usr/bin/env python3
#
#  node_source.py — a fleet node as a source of observations.
#
#  Why this exists: a module surveys something — cells, GSMTAP, captures, a SIM
#  — and until now "something" meant this machine. A node in the fleet may be
#  the only thing that can hear the network: a handset already camped on it, a
#  dongle holding a serving cell, a box in another city with an SDR on the roof.
#  This is the one place that knows how to ask those devices, and the one place
#  that refuses when a device cannot answer in the shape the caller needs.
#
#  The contract is the tree's: TSV on stdout, one row per fact, ERROR/WHY on
#  stderr, exit 0 measured · 1 could not · 2 refused · 3 handoff. A field the
#  node did not report stays empty; nothing here fills a gap with a guess.
#
#  Two shapes come out of here: `cells`, the survey store's own table, and
#  `events`, the node's spool in the kind/epoch/src/type/len/detail table any
#  capture consumer can read. A module asks for the shape it already stores.
#
#  usage: node_source.py cells <node> [--header] [--out FILE]
#         node_source.py events <node> [--since N]
#         node_source.py captures <node> [--newest | --fetch PATH] [--dir DIR]
#         node_source.py facts <node>
#         node_source.py support
#         node_source.py selftest

import argparse
import os
import shlex
import shutil
import socket
import subprocess
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import casebook  # noqa: E402  — one writer for the node table and the AT wire

# The store cell recon writes, and the only shape a caller gets from `cells`:
#   rat gen arfcn freq_mhz plmn mcc mnc operator country cell_id tac_lac band
#   rsrp_dbm cipher source ts
CELL_FIELDS = ["rat", "gen", "arfcn", "freq_mhz", "plmn", "mcc", "mnc",
               "operator", "country", "cell_id", "tac_lac", "band",
               "rsrp_dbm", "cipher", "source", "ts"]

# E-UTRA downlink ranges: (N_DL low, N_DL high, F_DL low in MHz).
EUTRA_DL = [
    (0, 599, 2110.0), (600, 1199, 1930.0), (1200, 1949, 1805.0),
    (1950, 2399, 2110.0), (2400, 2649, 869.0), (2650, 2749, 875.0),
    (2750, 3449, 2620.0), (3450, 3799, 925.0), (3800, 4149, 1844.9),
    (4150, 4749, 2110.0), (4750, 4949, 1475.9), (5010, 5179, 729.0),
    (5180, 5279, 746.0), (5280, 5379, 758.0), (5730, 5849, 734.0),
    (5850, 5999, 860.0), (6000, 6149, 875.0), (6150, 6449, 791.0),
    (6450, 6599, 1495.9), (6600, 7399, 3510.0), (7500, 7699, 2180.0),
    (7700, 8039, 1525.0), (8040, 8689, 1930.0), (8690, 9039, 859.0),
    (9040, 9209, 852.0), (9210, 9659, 758.0), (9770, 9869, 2350.0),
    (9870, 9919, 462.5), (36000, 36199, 1900.0), (36200, 36349, 2010.0),
    (36350, 36949, 1850.0), (36950, 37549, 1930.0), (37550, 37749, 1910.0),
    (37750, 38249, 2570.0), (38250, 38649, 1880.0), (38650, 39649, 2300.0),
    (39650, 41589, 2496.0), (41590, 43589, 3400.0), (43590, 45589, 3600.0),
    (45590, 46589, 703.0), (65536, 66435, 2110.0), (66436, 67335, 2110.0),
    (67336, 67535, 738.0), (67536, 67835, 753.0), (68586, 68935, 617.0),
]

# Access technology as AT+COPS and CellInfo both spell it, in the three words
# the rest of the tree already uses.
RAT_WORDS = {
    "lte": "4G", "4g": "4G", "eutran": "4G", "eutra": "4G",
    "nr": "5G", "5g": "5G", "nrar": "5G",
    "umts": "3G", "3g": "3G", "utran": "3G", "hspa": "3G", "wcdma": "3G",
    "gsm": "2G", "2g": "2G", "geran": "2G", "gprs": "2G", "edge": "2G",
}

# 3GPP TS 27.007 <act> values, which is what AT+COPS? and AT+CEREG? report.
ACT_WORDS = {
    "0": "gsm", "1": "gsm", "3": "gsm",
    "2": "umts", "4": "umts", "5": "umts", "6": "umts",
    "7": "lte", "10": "lte",
    "11": "nr", "13": "nr",
}

# What each transport can honestly deliver for a cell survey, and why the rest
# cannot. This table is the answer to "can I survey from that node?" and it is
# printed by `support`, so a person never has to read the code to find out.
SUPPORT = {
    "local": ("survey", "runs this tree's own cell recon on the node"),
    "ssh": ("survey", "runs cell recon on the node and reads its store back"),
    "adb": ("handset", "the handset's own view: serving cell plus its "
                       "neighbours, with what the OS withholds marked"),
    "serial": ("serving", "AT: one serving cell, no survey of the band"),
    "qmi": ("serving", "one serving cell from the modem, no survey"),
    "mbim": ("serving", "device capabilities and the serving system"),
    "diag": ("refuse", "the diag wire has no transport in this toolkit"),
    "sms": ("refuse", "SMS is an out-of-band keyhole, not a survey"),
}


def emit(key, value):
    sys.stdout.write("%s\t%s\n" % (key, value))


def refuse(message, why):
    sys.stderr.write("ERROR\t%s\n" % message)
    sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(2)


def handoff(message, why):
    sys.stderr.write("ERROR\t%s\n" % message)
    sys.stderr.write("WHY\t%s\n" % why)
    raise SystemExit(3)


def clean(value):
    """A value that cannot forge a column: tabs and newlines become spaces."""
    if value is None:
        return ""
    return " ".join(str(value).replace("\t", " ").split("\n")).strip()


def gen_of_rat(rat):
    return RAT_WORDS.get((rat or "").strip().lower(), "")


def earfcn_mhz(earfcn):
    """LTE EARFCN to downlink MHz, TS 36.101 table 5.7.3-1.

    Every band carries its own offset, so this is a table and not a formula: a
    first version with five ranges answered about half the bands and returned
    nothing for the other half, which reads in a table as "this cell has no
    frequency" rather than "this code does not know".
    """
    try:
        n = int(str(earfcn).strip())
    except (TypeError, ValueError):
        return ""
    for low, high, f_low in EUTRA_DL:
        if low <= n <= high:
            return "%.4f" % (f_low + 0.1 * (n - low))
    return ""


def arfcn_mhz(arfcn):
    """GSM ARFCN to downlink MHz, TS 45.005 clause 2."""
    try:
        n = int(str(arfcn).strip())
    except (TypeError, ValueError):
        return ""
    if 0 <= n <= 124:
        return "%.1f" % (935.0 + 0.2 * n)
    if 128 <= n <= 251:
        return "%.1f" % (935.0 + 0.2 * (n - 128))
    if 512 <= n <= 885:
        return "%.1f" % (1805.2 + 0.2 * (n - 512))
    if 940 <= n <= 1023:
        return "%.1f" % (890.0 + 0.2 * (n - 940))
    return ""


def freq_of(rat, arfcn):
    gen = gen_of_rat(rat)
    if gen == "4G":
        return earfcn_mhz(arfcn)
    if gen == "2G":
        return arfcn_mhz(arfcn)
    return ""


def split_plmn(text):
    """A PLMN in any of the three spellings the tree sees, to (mcc, mnc)."""
    digits = "".join(ch for ch in clean(text) if ch.isdigit())
    if len(digits) >= 5:
        return digits[:3], digits[3:6]
    return "", ""


def row(**kw):
    """One cell row in the store's own column order."""
    values = []
    for field in CELL_FIELDS:
        values.append(clean(kw.get(field, "")))
    sys.stdout.write("\t".join(values) + "\n")


def cell_row(rat, plmn="", cell_id="", tac="", arfcn="", rsrp="", source="",
             band="", cipher=""):
    mcc, mnc = split_plmn(plmn)
    row(rat=rat, gen=gen_of_rat(rat),
        arfcn=arfcn, freq_mhz=freq_of(rat, arfcn),
        plmn=("%s-%s" % (mcc, mnc)) if mcc else "",
        mcc=mcc, mnc=mnc,
        # No operator name: the node reported digits, and a lookup table in
        # this file would be a second operator list to keep current.
        operator="",
        country="", cell_id=cell_id, tac_lac=tac, band=band,
        rsrp_dbm=rsrp, cipher=cipher, source=source, ts=casebook.now())


def load_node(name):
    rows = casebook.read_table(casebook.NODES, casebook.NODE_FIELDS)
    node = next((r for r in rows if r.get("name") == name), None)
    if node is None:
        refuse("unknown node: %s" % name,
               "register it first: 59_remote_node.sh --add %s <host> "
               "--transport ssh" % name)
    return node


def transport_of(node):
    return casebook.node_field(node, "transport") or "ssh"


def source_tag(name, transport, kind):
    return "node:%s:%s:%s" % (name, transport, kind)


# ── local and ssh: the node runs this tree's own survey ─────────────────
def cells_local(node, name):
    script = casebook.ROOT / "modules" / "02_cell_recon.sh"
    if not script.exists():
        refuse("no cell recon in %s" % casebook.ROOT,
               "a local node IS this machine, so the module has to be here")
    # Run the module the way the launcher does — its own shebang. Invoking it
    # with `sh` fails on the first [[ that this tree's modules open with, and
    # the failure arrives as "cell recon on the local node failed" rather than
    # as "you called me with the wrong shell".
    argv = [str(script), "--list-tsv"]
    if not os.access(script, os.X_OK):
        argv = ["bash", str(script), "--list-tsv"]
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        if "no survey store" in (proc.stderr or ""):
            handoff("the node has not surveyed anything yet",
                    "run a survey there: 02_cell_recon.sh --scan gsm")
        refuse("cell recon on the local node failed",
               (proc.stderr or proc.stdout or "").strip()[:200])
    return copy_rows(proc.stdout, node, name, transport_of(node))


def node_command(node):
    """How to run a module on an ssh node: its own tree, else the wrapper."""
    root = casebook.node_field(node, "root") or ""
    if root:
        return "cd %s && modules/02_cell_recon.sh" % shlex.quote(root)
    return "imsisting --npm-module 02_cell_recon --"


def cells_ssh(node, name):
    host = casebook.node_field(node, "host")
    port = casebook.node_field(node, "port")
    command = node_command(node) + " --list-tsv"
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if port:
        argv += ["-p", port]
    argv += [host, command]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.TimeoutExpired) as exc:
        refuse("could not ask %s for its survey: %s" % (name, exc),
               "an unreachable node is not an empty survey")
    out = proc.stdout or ""
    if proc.returncode != 0:
        message = (proc.stderr or "").strip()[:200]
        if "imsisting: not found" in message or "No such file" in message:
            handoff("%s has no survey to read: the toolkit is not on that node"
                    % name, "install it there (npm i -g imsisting) or set "
                            "'root' on the node row, then probe it again")
        refuse("cell recon on %s failed" % name, message or "no reason given")
    return copy_rows(out, node, name, "ssh")


def copy_rows(text, node, name, transport):
    """Rows a node already surveyed, re-sourced so nobody mistakes the origin."""
    lines = [l for l in (text or "").splitlines() if l.strip()]
    if not lines:
        handoff("%s surveyed nothing" % name,
                "its store is empty; run a survey on that node first")
    # `--list-tsv` prints rows only; a node that handed back its whole store
    # prints the header first. Both are the same table, so the header is
    # recognised where it appears rather than demanded.
    if lines[0].split("\t")[:len(CELL_FIELDS)] == CELL_FIELDS:
        lines = lines[1:]
    else:
        width = len(lines[0].split("\t"))
        if width != len(CELL_FIELDS):
            refuse("%s returned a table this module does not know" % name,
                   "first line had %d columns, expected %d: %s"
                   % (width, len(CELL_FIELDS), lines[0][:120]))
    tag = source_tag(name, transport, "survey")
    count = 0
    for line in lines:
        fields = line.split("\t")
        if len(fields) < len(CELL_FIELDS):
            fields += [""] * (len(CELL_FIELDS) - len(fields))
        values = dict(zip(CELL_FIELDS, fields))
        values["source"] = tag
        sys.stdout.write("\t".join(clean(values[f]) for f in CELL_FIELDS) + "\n")
        count += 1
    if count == 0:
        handoff("%s has an empty survey store" % name,
                "a header with no rows is not a survey")
    return 0


# ── adb: the handset's own view ─────────────────────────────────────────
def cells_adb(node, name):
    serial = casebook.node_field(node, "host")
    agent = casebook.ROOT / "tools" / "ue_agent.sh"
    if not agent.exists():
        refuse("ue_agent.sh is missing",
               "the handset side of this tree is how a phone is asked anything")
    argv = ["sh", str(agent), "--cells"]
    if serial:
        argv += ["--serial", serial]
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode not in (0,):
        refuse("the handset did not answer: %s" % name,
               (proc.stdout or proc.stderr or "").strip()[:200])
    facts = {}
    for line in (proc.stdout or "").splitlines():
        if "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        facts.setdefault(key, []).append(value)
    status = (facts.get("status") or [""])[0]
    if status == "no-cell-info":
        handoff("%s printed no cell info" % name,
                "the handset may be idle, or the OS withheld the registry")
    blocks = 0
    try:
        blocks = int((facts.get("blocks") or ["0"])[0])
    except ValueError:
        blocks = 0
    tag = source_tag(name, "adb", "handset")
    written = 0
    for index in range(1, blocks + 1):
        prefix = "cells.%d." % index
        cell = {k[len(prefix):]: v[0] for k, v in facts.items()
                if k.startswith(prefix)}
        if not cell:
            continue
        rat = (cell.get("rat") or "").lower()
        arfcn = cell.get("Earfcn") or cell.get("mEarfcn") or ""
        cell_id = cell.get("Ci") or cell.get("mCi") or ""
        tac = cell.get("Tac") or cell.get("mTac") or ""
        mcc = cell.get("Mcc") or cell.get("mMcc") or ""
        mnc = cell.get("Mnc") or cell.get("mMnc") or ""
        rsrp = cell.get("Rsrp") or cell.get("mRsrp") or ""
        # A handset reports a cell it can see; it does not sweep a band. The
        # source tag says which of those this row is.
        cell_row(rat=rat, plmn="%s%s" % (mcc, mnc) if mcc else "",
                 cell_id=cell_id, tac=tac, arfcn=arfcn, rsrp=rsrp,
                 source=tag, band=cell.get("Band") or "")
        written += 1
    if written == 0:
        handoff("%s reported no usable cell" % name,
                "the blocks carried no identity this module can store")
    return 0


# ── AT: one serving cell, honestly named as one ─────────────────────────
def at_serving(node, name):
    host = casebook.node_field(node, "host")
    port = casebook.node_field(node, "port")
    try:
        channel = casebook.at_channel(host, port)
    except Exception as exc:                     # noqa: BLE001 — the wire, not us
        refuse("could not open %s: %s" % (host, exc),
               "a modem that does not answer AT cannot report a cell")
    try:
        cops = casebook.at_talk(channel, "AT+COPS?")
        csq = casebook.at_talk(channel, "AT+CSQ")
        creg = casebook.at_talk(channel, "AT+CREG?")
        cereg = casebook.at_talk(channel, "AT+CEREG?")
    finally:
        casebook.at_close(channel)

    act = ""
    cops_body = casebook.at_value(cops, "+COPS")
    for part in (cops_body or "").split(","):
        token = part.strip().strip('"')
        if token in ACT_WORDS:
            act = ACT_WORDS[token]
            break
    rat = act or "unknown"

    rsrp = ""
    csq_body = casebook.at_value(csq, "+CSQ")
    if csq_body:
        first = csq_body.split(",")[0].strip()
        if first.isdigit() and int(first) != 99:
            rsrp = str(-113 + 2 * int(first))

    cell_id, tac = "", ""
    cereg_body = casebook.at_value(cereg, "+CEREG")
    if cereg_body and "," in cereg_body:
        parts = [p.strip().strip('"') for p in cereg_body.split(",")]
        if len(parts) >= 4:
            tac, cell_id = parts[2], parts[3]
    if not cell_id:
        creg_body = casebook.at_value(creg, "+CREG")
        if creg_body and "," in creg_body:
            parts = [p.strip().strip('"') for p in creg_body.split(",")]
            if len(parts) >= 4:
                tac, cell_id = parts[2], parts[3]

    plmn = ""
    if cops_body:
        quoted = [p.strip() for p in cops_body.split(",")]
        if len(quoted) >= 3:
            candidate = quoted[2].strip('"')
            if candidate.isdigit() or ("-" in candidate):
                plmn = candidate

    if not cell_id and not plmn:
        handoff("%s answered AT but reported no cell" % name,
                "the modem is registered to nothing, or its firmware keeps "
                "the serving cell behind a vendor command")

    cell_row(rat=rat, plmn=plmn, cell_id=cell_id, tac=tac, rsrp=rsrp,
             source=source_tag(name, transport_of(node), "serving"))
    return 0


def cells_qmi(node, name):
    dev = casebook.node_field(node, "host")
    tool = shutil.which("uqmi")
    if tool is None:
        refuse("uqmi is not installed here",
               "a QMI modem is read with uqmi; the node itself may have it, "
               "and then this verb belongs on that node")
    proc = subprocess.run([tool, "-d", dev, "--get-serving-system"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        refuse("uqmi could not read %s" % dev, (proc.stderr or "").strip()[:200])
    import json
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        refuse("uqmi printed something that is not JSON",
               (proc.stdout or "").strip()[:200])
    if not data.get("registered", True):
        handoff("%s is not registered to a network" % name,
                "an unregistered modem has no serving cell to report")
    cell_row(rat=str(data.get("radio_interface", "") or "").lower(),
             plmn=str(data.get("plmn", "") or ""),
             cell_id=str(data.get("cell_id", "") or ""),
             tac=str(data.get("tac", "") or ""),
             source=source_tag(name, "qmi", "serving"))
    return 0


def cells_mbim(node, name):
    tool = shutil.which("mbimcli")
    if tool is None:
        refuse("mbimcli is not installed here",
               "an MBIM modem is read with mbimcli; see 'support' for what "
               "each transport can answer")
    refuse("MBIM serving-system parsing is not built",
           "mbimcli's device-caps output does not carry a cell identity, and "
           "the registration state it does carry is not a survey")


CELLS_BY_TRANSPORT = {
    "local": cells_local,
    "ssh": cells_ssh,
    "adb": cells_adb,
    "serial": at_serving,
    "qmi": cells_qmi,
    "mbim": cells_mbim,
}


def cmd_cells(args):
    node = load_node(args.node)
    transport = transport_of(node)
    kind, why = SUPPORT.get(transport, ("refuse", "unknown transport"))
    if kind == "refuse":
        refuse("%s cannot survey: %s" % (args.node, why),
               "register the node over ssh, local, adb, serial or qmi, or "
               "survey from this machine")
    handler = CELLS_BY_TRANSPORT.get(transport)
    if handler is None:
        refuse("no reader for transport %s" % transport, why)
    if args.header:
        sys.stdout.write("\t".join(CELL_FIELDS) + "\n")
    return handler(node, args.node)


EVENT_FIELDS = ["kind", "epoch", "src", "type", "len", "detail"]

# Only these kinds are events. The agent also emits bookkeeping rows (spool,
# source, size) and a drained stream carries the casebook's own meta; a feed
# that shows those is showing its own plumbing to the operator.
EVENT_KINDS = ("gsmtap", "radio", "beat", "capture")


CAPTURE_FIELDS = ["node", "path", "size", "mtime", "kind"]
CAPTURE_SUFFIXES = {".pcap": "pcap", ".pcapng": "pcapng", ".tsv": "tsv",
                    ".log": "log", ".csv": "csv"}


def capture_kind(path):
    suffix = Path(path).suffix.lower()
    return CAPTURE_SUFFIXES.get(suffix, "file")


def local_captures_dir():
    return Path(casebook.ROOT) / "captures"


def node_captures_dir(node):
    """Where a node keeps captures, when the node has its own tree."""
    return casebook.node_field(node, "root") or ""


def list_captures(node, name):
    """(path, size, mtime) for every capture the node will offer.

    A capture store that is missing and a capture store that is empty are the
    same three columns and a different answer, so they are not the same exit.
    """
    transport = transport_of(node)
    if transport == "local":
        root = local_captures_dir()
        if not root.exists():
            handoff("no capture store on this machine",
                    "expected %s; capture something first" % root)
        found = []
        # captures/nodes/<name>/ is where fetches land. Listing it back would
        # offer a node its own copies and grow a copy of a copy each time.
        fetch_root = root / "nodes"
        for path in sorted(root.rglob("*")):
            if fetch_root in path.parents:
                continue
            if path.is_file() and path.suffix.lower() in CAPTURE_SUFFIXES:
                stat = path.stat()
                found.append((str(path), stat.st_size, int(stat.st_mtime)))
        return found
    if transport == "ssh":
        host = casebook.node_field(node, "host")
        port = casebook.node_field(node, "port")
        base = node_captures_dir(node)
        prefix = shlex.quote(base + "/captures") if base.startswith("/") \
            else "$HOME/IMSIsting/captures"
        command = ("cd %s 2>/dev/null && find . -maxdepth 3 -type f "
                   "-printf '%%p\\t%%s\\t%%T@\\n' || exit 44" % prefix)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
        if port:
            argv += ["-p", port]
        argv += [host, command]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=40)
        except (OSError, subprocess.TimeoutExpired) as exc:
            refuse("could not ask %s for its captures: %s" % (name, exc),
                   "an unreachable node is not an empty capture store")
        if proc.returncode == 44:
            handoff("%s has no capture store" % name,
                    "capture something there, or set 'root' on the node row")
        if proc.returncode != 0:
            refuse("listing captures on %s failed" % name,
                   (proc.stderr or "").strip()[:200])
        found = []
        for line in (proc.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            rel, size, mtime = parts[0], parts[1], parts[2]
            if Path(rel).suffix.lower() not in CAPTURE_SUFFIXES:
                continue
            try:
                found.append((rel, int(float(size)), int(float(mtime))))
            except ValueError:
                continue
        return found
    kind, why = SUPPORT.get(transport, ("refuse", "unknown transport"))
    refuse("%s has no capture store: %s" % (name, why),
           "a handset or a modem does not archive captures; pull its radio log "
           "with ue_agent.sh --radio-log instead")


def fetch_capture(node, name, wanted):
    """Copy one capture here and print where it landed."""
    transport = transport_of(node)
    stamp = casebook.now().replace(":", "").replace("-", "")
    destination = Path(casebook.ROOT) / "captures" / "nodes" / name
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / ("%s-%s" % (stamp[:15], Path(wanted).name))
    if transport == "local":
        source = Path(wanted)
        if not source.is_absolute():
            source = local_captures_dir() / wanted
        if not source.exists():
            refuse("no such capture on this machine: %s" % wanted,
                   "list them first: node_source.py captures <node>")
        shutil.copy2(source, target)
    elif transport == "ssh":
        host = casebook.node_field(node, "host")
        port = casebook.node_field(node, "port")
        base = node_captures_dir(node)
        base = (base + "/captures") if base else ""
        if base and not wanted.startswith("/"):
            remote = "%s/%s" % (base, wanted)
        elif wanted.startswith("/"):
            remote = wanted
        else:
            remote = "$HOME/IMSIsting/captures/%s" % wanted
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
        if port:
            argv += ["-p", port]
        argv += [host, "cat %s" % shlex.quote(remote)]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            refuse("could not fetch %s from %s: %s" % (wanted, name, exc),
                   "the node stopped answering between the list and the fetch")
        if proc.returncode != 0 or not proc.stdout:
            refuse("could not read %s on %s" % (wanted, name),
                   (proc.stderr or b"").decode("utf-8", "replace").strip()[:200]
                   or "the file is empty")
        target.write_bytes(proc.stdout)
    else:
        refuse("%s cannot hand over a capture" % name,
               SUPPORT.get(transport, ("refuse", ""))[1])
    emit("fetched", str(target))
    emit("bytes", target.stat().st_size if target.exists() else 0)
    return 0


def cmd_captures(args):
    node = load_node(args.node)
    if args.fetch:
        return fetch_capture(node, args.node, args.fetch)
    found = list_captures(node, args.node)
    if args.newest:
        if not found:
            handoff("%s has no captures" % args.node,
                    "capture something there first")
        newest = max(found, key=lambda item: item[2])
        return fetch_capture(node, args.node, newest[0])
    for path, size, mtime in found:
        row = {"node": args.node, "path": path, "size": size,
               "mtime": casebook.stamp(mtime) if hasattr(casebook, "stamp")
               else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)),
               "kind": capture_kind(path)}
        sys.stdout.write("\t".join(clean(row[f]) for f in CAPTURE_FIELDS) + "\n")
    emit("count", len(found))
    return 0


def cmd_events(args):
    node = load_node(args.node)
    transport = transport_of(node)
    if transport in ("diag", "sms"):
        refuse("%s cannot stream: %s" % (args.node, SUPPORT[transport][1]),
               "an event stream needs a transport that carries packets")
    since = 0
    if args.since:
        try:
            since = int(args.since)
        except ValueError:
            refuse("--since wants a byte offset", "got %r" % args.since)
    rc, meta, body = casebook.stream_pull(node, since)
    if rc != 0:
        # A node that answered nothing is unreachable, not quiet. Saying so is
        # the difference between "no events" and "nobody asked".
        refuse("%s did not answer for its spool" % args.node,
               "the node is unreachable or its agent is missing; probe it first")
    emit("source", meta.get("source", "") or "spool")
    emit("spool", meta.get("spool", ""))
    emit("size", meta.get("size", "0"))
    count = 0
    for line in (body or "").splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if fields[0] not in EVENT_KINDS:
            continue
        fields += [""] * (len(EVENT_FIELDS) - len(fields))
        row = dict(zip(EVENT_FIELDS, fields))
        row["src"] = row.get("src") or args.node
        sys.stdout.write("\t".join(clean(row[f]) for f in EVENT_FIELDS) + "\n")
        count += 1
    emit("rows", count)
    return 0


def cmd_facts(args):
    node = load_node(args.node)
    transport = transport_of(node)
    kind, why = SUPPORT.get(transport, ("refuse", "unknown transport"))
    emit("node", args.node)
    emit("transport", transport)
    emit("class", casebook.node_field(node, "class") or "-")
    emit("status", casebook.node_field(node, "status") or "UNKNOWN")
    emit("survey_kind", kind)
    emit("survey_note", why)
    emit("caps", casebook.node_field(node, "caps") or "-")
    return 0


def cmd_support(_):
    emit("transport", "kind\tnote")
    for transport in sorted(SUPPORT):
        kind, why = SUPPORT[transport]
        emit(transport, "%s\t%s" % (kind, why))
    return 0


# ── selftest: the mapping and the refusals, with no hardware ────────────
def selftest():
    import io
    import os
    import tempfile
    import threading

    failures = []

    def check(name, got, want):
        ok = got == want
        print("%s\t%s\t%s" % ("PASS" if ok else "FAIL", name,
                              "got=%r want=%r" % (got, want) if not ok else ""))
        if not ok:
            failures.append(name)

    check("gen-of-rat-lte", gen_of_rat("LTE"), "4G")
    check("gen-of-rat-nr", gen_of_rat("nr"), "5G")
    check("gen-of-rat-gsm", gen_of_rat("GSM"), "2G")
    check("gen-of-rat-unknown", gen_of_rat("watts"), "")
    check("earfcn-6300", earfcn_mhz(6300), "806.0000")
    check("earfcn-1300", earfcn_mhz(1300), "1815.0000")
    check("earfcn-junk", earfcn_mhz("x"), "")
    check("arfcn-42", arfcn_mhz(42), "943.4")
    check("arfcn-700", arfcn_mhz(700), "1842.8")
    check("plmn-dashed", split_plmn("262-01"), ("262", "01"))
    check("plmn-bare", split_plmn("26201"), ("262", "01"))
    check("plmn-none", split_plmn(""), ("", ""))
    check("clean-tabs", clean("a\tb\nc"), "a b c")
    check("act-lte", ACT_WORDS.get("7"), "lte")
    check("act-nr", ACT_WORDS.get("11"), "nr")

    # adb: ue_cells rows in, store rows out
    fixture = "\n".join([
        "status\tcell-seen",
        "blocks\t2",
        "cells.1.Source\tCellInfo",
        "cells.1.rat\tlte",
        "cells.1.Ci\t1234567",
        "cells.1.Tac\t42",
        "cells.1.Earfcn\t6300",
        "cells.1.Mcc\t262",
        "cells.1.Mnc\t01",
        "cells.1.Rsrp\t-97",
        "cells.2.rat\tgsm",
        "cells.2.Ci\t7788",
        "cells.2.Tac\t7",
    ]) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        book = Path(tmp) / "book"
        book.mkdir()
        nodes = book / "nodes.tsv"
        nodes.write_text("\t".join(casebook.NODE_FIELDS) + "\n"
                         + "\t".join(["handset", "R58M12345", "", "adb", "phone",
                                      "ue", "", "", casebook.now(), "", "ONLINE",
                                      ""]) + "\n")
        old_book, old_root = casebook.BOOK, getattr(casebook, "ROOT", None)
        casebook.BOOK = book
        casebook.NODES = nodes
        fake_agent = Path(tmp) / "ue_agent.sh"
        fake_agent.write_text("#!/bin/sh\ncat <<'ROWS'\n" + fixture + "ROWS\n")
        old_agent = getattr(casebook, "ROOT")
        casebook.ROOT = Path(tmp)
        (Path(tmp) / "tools").mkdir()
        (Path(tmp) / "tools" / "ue_agent.sh").write_text(fake_agent.read_text())

        out = io.StringIO()
        real_stdout, sys.stdout = sys.stdout, out
        try:
            rc = cells_adb(casebook.read_table(nodes, casebook.NODE_FIELDS)[0],
                           "handset")
        finally:
            sys.stdout = real_stdout
            casebook.BOOK = old_book
            casebook.ROOT = old_agent
        rows = [l.split("\t") for l in out.getvalue().splitlines() if l]
        check("adb-rc", rc, 0)
        check("adb-rows", len(rows), 2)
        first = dict(zip(CELL_FIELDS, rows[0])) if rows else {}
        check("adb-rat", first.get("rat"), "lte")
        check("adb-gen", first.get("gen"), "4G")
        check("adb-cell", first.get("cell_id"), "1234567")
        check("adb-plmn", first.get("plmn"), "262-01")
        check("adb-freq", first.get("freq_mhz"), "806.0000")
        check("adb-source", first.get("source"), "node:handset:adb:handset")
        # A handset that prints no identity is a handoff, never an empty table.
        with tempfile.TemporaryDirectory() as tmp2:
            (Path(tmp2) / "tools").mkdir()
            (Path(tmp2) / "tools" / "ue_agent.sh").write_text(
                "#!/bin/sh\nprintf 'status\\tcell-seen\\nblocks\\t1\\n'\n")
            saved = casebook.ROOT
            casebook.ROOT = Path(tmp2)
            real_stdout, sys.stdout = sys.stdout, io.StringIO()
            try:
                cells_adb({"name": "n", "host": "", "transport": "adb"}, "n")
                rc2 = 0
            except SystemExit as exc:
                rc2 = exc.code
            finally:
                sys.stdout = real_stdout
                casebook.ROOT = saved
            check("adb-empty-handoff", rc2, 3)

    # A node's `--list-tsv` prints rows with no header; the same code path must
    # accept a store dump that does print one, and must refuse a table of the
    # wrong width instead of guessing which column is which.
    headerless = "\t".join(["lte", "4G", "6300", "806.0000", "262-01", "262",
                            "01", "", "", "1234567", "42", "", "", "", "local",
                            "2026-10-25T10:00:00Z"]) + "\n"
    out = io.StringIO()
    real_stdout, sys.stdout = sys.stdout, out
    try:
        rc = copy_rows(headerless, {"name": "n"}, "n", "local")
    finally:
        sys.stdout = real_stdout
    rows = [l.split("\t") for l in out.getvalue().splitlines() if l]
    check("copy-rows-headerless-rc", rc, 0)
    check("copy-rows-headerless-count", len(rows), 1)
    check("copy-rows-resourced",
          dict(zip(CELL_FIELDS, rows[0])).get("source") if rows else "",
          "node:n:local:survey")
    out = io.StringIO()
    real_stdout, sys.stdout = sys.stdout, out
    try:
        copy_rows("rat\tgen\n", {"name": "n"}, "n", "local")
        rc = 0
    except SystemExit as exc:
        rc = exc.code
    finally:
        sys.stdout = real_stdout
    check("copy-rows-wrong-width", rc, 2)

    # events: the spool's own rows, with bookkeeping filtered out
    with tempfile.TemporaryDirectory() as tmp:
        book = Path(tmp) / "book"
        book.mkdir()
        nodes = book / "nodes.tsv"
        nodes.write_text("\t".join(casebook.NODE_FIELDS) + "\n"
                         + "\t".join(["desk", "localhost", "", "local", "sdr",
                                      "sensor", "", "-", casebook.now(),
                                      casebook.now(), "ONLINE", ""]) + "\n")
        spool = Path(tmp) / "spool.tsv"
        spool.write_text("kind\tepoch\tsrc\ttype\tlen\tdetail\n"
                         "gsmtap\t1792915200\teth0\t1\t58\tvia=tshark\n"
                         "spool\t1792915201\tdesk\t-\t0\tbookkeeping\n"
                         "beat\t1792915202\tdesk\t-\t0\tuptime=100\n")
        saved_book, saved_nodes = casebook.BOOK, casebook.NODES
        saved_env = {k: os.environ.get(k) for k in ("NODE_SPOOL", "NODE_STREAM_WINDOW")}
        casebook.BOOK, casebook.NODES = book, nodes
        os.environ["NODE_SPOOL"] = str(spool)
        os.environ["NODE_STREAM_WINDOW"] = "1"
        out = io.StringIO()
        real_stdout, sys.stdout = sys.stdout, out
        try:
            rc = cmd_events(argparse.Namespace(node="desk", since=""))
        finally:
            sys.stdout = real_stdout
            casebook.BOOK, casebook.NODES = saved_book, saved_nodes
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        rows = [l.split("\t") for l in out.getvalue().splitlines() if l]
        kinds = [r[0] for r in rows]
        check("events-rc", rc, 0)
        check("events-gsmtap", "gsmtap" in kinds, True)
        check("events-beat", "beat" in kinds, True)
        check("events-no-bookkeeping", kinds.count("spool"), 1)
        check("events-meta-rows", kinds[:3], ["source", "spool", "size"])

    # captures: listing skips the fetch destination, fetching lands a copy
    with tempfile.TemporaryDirectory() as tmp:
        book = Path(tmp) / "book"
        book.mkdir()
        nodes = book / "nodes.tsv"
        nodes.write_text("\t".join(casebook.NODE_FIELDS) + "\n"
                         + "\t".join(["desk", "localhost", "", "local", "sdr",
                                      "sensor", "", "-", casebook.now(),
                                      casebook.now(), "ONLINE", ""]) + "\n")
        root = Path(tmp) / "root"
        (root / "captures" / "nodes" / "desk").mkdir(parents=True)
        (root / "captures" / "one.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
        (root / "captures" / "notes.txt").write_text("not a capture")
        (root / "captures" / "nodes" / "desk" / "old.pcap").write_bytes(b"old")
        saved = (casebook.BOOK, casebook.NODES, casebook.ROOT)
        casebook.BOOK, casebook.NODES, casebook.ROOT = book, nodes, root
        out = io.StringIO()
        real_stdout, sys.stdout = sys.stdout, out
        try:
            rc = cmd_captures(argparse.Namespace(node="desk", newest=False,
                                                 fetch=""))
        finally:
            sys.stdout = real_stdout
            casebook.BOOK, casebook.NODES, casebook.ROOT = saved
        rows = [l.split("\t") for l in out.getvalue().splitlines() if l]
        listed = [r[1] for r in rows if len(r) > 1 and r[0] == "desk"]
        check("captures-rc", rc, 0)
        check("captures-finds-pcap", any(p.endswith("one.pcap") for p in listed), True)
        check("captures-skips-other-files",
              any(p.endswith("notes.txt") for p in listed), False)
        # A fetched copy must not be offered back as if the node made it.
        check("captures-skips-fetch-dir",
              any("/nodes/desk/" in p for p in listed), False)
        check("captures-kind", capture_kind("x.pcapng"), "pcapng")
        check("captures-kind-other", capture_kind("x.bin"), "file")

    # support table names every transport the casebook allows
    for transport in casebook.NODE_TRANSPORTS:
        check("support-%s" % transport, transport in SUPPORT, True)

    print("RESULT\t%s" % ("FAIL" if failures else "PASS"))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="command")
    cells = sub.add_parser("cells")
    cells.add_argument("node")
    cells.add_argument("--header", action="store_true")
    caps = sub.add_parser("captures")
    caps.add_argument("node")
    caps.add_argument("--newest", action="store_true")
    caps.add_argument("--fetch", default="")
    events = sub.add_parser("events")
    events.add_argument("node")
    events.add_argument("--since", default="")
    facts = sub.add_parser("facts")
    facts.add_argument("node")
    sub.add_parser("support")
    sub.add_parser("selftest")
    args = parser.parse_args(argv)
    if args.command == "cells":
        return cmd_cells(args)
    if args.command == "captures":
        return cmd_captures(args)
    if args.command == "events":
        return cmd_events(args)
    if args.command == "facts":
        return cmd_facts(args)
    if args.command == "support":
        return cmd_support(args)
    if args.command == "selftest":
        return selftest()
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
