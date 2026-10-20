#!/usr/bin/env bash
# Check the SMPP 3.4 PDUs `41_ota_sms --smpp-build` / `--smpp-response` build
# against an outside implementation: the tshark SMPP dissector, plus the octet
# spine each PDU claims.
#
# Why this exists: an SMPP PDU is a length field, a command id and a body of
# C-Octet Strings whose terminating NUL counts in the field, so an encoder that
# only agrees with itself can still be wrong about one boundary and stay
# silent -- every field after a missing NUL shifts by an octet. This checker
# therefore builds each PDU through the module's own CLI, wraps it in a real
# TCP/2775 capture (three-way handshake, then the payload), and asks tshark
# where each field starts and how long it is. Two independent statements must
# agree: this script's own field table, read from the SMPP 3.4 PDU definitions,
# and the dissector's. Then the spine is walked octet by octet: the first four
# octets must equal the actual PDU size, and every C-Octet String must stop at
# a 0x00 exactly at the last octet the dissector gives that field.
#
# The negative control is a copy of the submit_sm PDU whose length field says
# 16 while the body is still there. tshark must call it malformed and the
# module must refuse it, which is what makes a PASS mean "the length field is
# read", not "the frames were ignored".
#
# Note on the port binding: Wireshark 4.2.2 ships the SMPP dissector (`-G
# fields` lists smpp.command_id) but `-G decodes` has no entry binding TCP 2775
# to it, so every call passes `-d tcp.port==2775,smpp`. Without that the capture
# would be plain TCP and the oracle would prove nothing.
#
# Exit codes:
#   0  every built PDU decodes as claimed and every refusal holds
#   1  a mismatch (the module is wrong, or the dissector moved)
#   2  SKIP -- tshark or python3 is absent, or tshark has no SMPP dissector.
#      A skip is not a pass: the summary line says so.
#
# Usage: tools/check-smpp.sh
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf 'SKIP\tno %s on PATH\n' "$PY"
    exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
    printf 'SKIP\ttshark is not on PATH, so no outside implementation can decode the built PDUs\n'
    exit 2
fi

"$PY" - "$ROOT" <<'SMPP_ORACLE'
import os
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = sys.argv[1]
MOD = os.path.join(ROOT, "modules", "41_ota_sms.sh")
THS = "tshark"
TMP = tempfile.mkdtemp(prefix="smpp-oracle.")
checks = 0
fails = 0


def ok(name, detail=""):
    global checks
    checks += 1
    print("PASS\t%s\t%s" % (name, detail))


def bad(name, detail):
    global checks, fails
    checks += 1
    fails += 1
    print("FAIL\t%s\t%s" % (name, detail))


def check(name, cond, detail=""):
    if cond:
        ok(name, detail)
    else:
        bad(name, detail)


def run(*args):
    return subprocess.run(["bash", MOD, *args], text=True, capture_output=True)


def rows(out):
    d = {}
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            d.setdefault(p[0], []).append(p[1])
    return d


def parse_fields(out):
    fs = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 6 and p[0] == "field":
            fs.append({"name": p[2], "off": int(p[1]), "kind": p[3], "hex": p[4], "disp": p[5]})
    return fs


# ── the spine, written from the SMPP 3.4 PDU definitions ────────────────
# One entry per body field, in wire order. "cstr" is a C-Octet String (the NUL
# is the last octet of the field); "u8" is one octet; "octets" is an Octet
# String whose length is the sm_length octet (short_message).
LAYOUT_SUBMIT = [
    ("service_type", "cstr"), ("source_addr_ton", "u8"), ("source_addr_npi", "u8"),
    ("source_addr", "cstr"), ("dest_addr_ton", "u8"), ("dest_addr_npi", "u8"),
    ("destination_addr", "cstr"), ("esm_class", "u8"), ("protocol_id", "u8"),
    ("priority_flag", "u8"), ("schedule_delivery_time", "cstr"), ("validity_period", "cstr"),
    ("registered_delivery", "u8"), ("replace_if_present_flag", "u8"), ("data_coding", "u8"),
    ("sm_default_msg_id", "u8"), ("sm_length", "u8"), ("short_message", "octets"),
]
LAYOUT_BIND = [
    ("system_id", "cstr"), ("password", "cstr"), ("system_type", "cstr"),
    ("interface_version", "u8"), ("addr_ton", "u8"), ("addr_npi", "u8"),
    ("address_range", "cstr"),
]
LAYOUT_BIND_RESP = [("system_id", "cstr")]
LAYOUT_MSG_RESP = [("message_id", "cstr")]

# module field name -> the tshark field that owns the same octets. esm_class
# and registered_delivery are bitfields to the dissector, so the check uses one
# of their subfields: the position and one-octet size are the same.
TSHARK_FIELD = {
    "service_type": "smpp.service_type",
    "source_addr_ton": "smpp.source_addr_ton",
    "source_addr_npi": "smpp.source_addr_npi",
    "source_addr": "smpp.source_addr",
    "dest_addr_ton": "smpp.dest_addr_ton",
    "dest_addr_npi": "smpp.dest_addr_npi",
    "destination_addr": "smpp.destination_addr",
    "esm_class": "smpp.esm.submit.msg_mode",
    "protocol_id": "smpp.protocol_id",
    "priority_flag": "smpp.priority_flag",
    "schedule_delivery_time": "smpp.schedule_delivery_time_r",
    "validity_period": "smpp.validity_period_r",
    "registered_delivery": "smpp.regdel.receipt",
    "replace_if_present_flag": "smpp.replace_if_present_flag",
    "data_coding": "smpp.data_coding",
    "sm_default_msg_id": "smpp.sm_default_msg_id",
    "sm_length": "smpp.sm_length",
    "short_message": "smpp.message",
    "system_id": "smpp.system_id",
    "password": "smpp.password",
    "interface_version": "smpp.interface_version",
    "addr_ton": "smpp.addr_ton",
    "addr_npi": "smpp.addr_npi",
    "address_range": "smpp.address_range",
    "message_id": "smpp.message_id",
}
# A NULL string is one 0x00 octet; the dissector may render no field at all
# for it (submit_sm_resp with message_id NULL does), so its absence is allowed.
MAY_BE_ABSENT = {"message_id"}


def spine(layout, pdu):
    """Walk the layout over the octets. Returns (fields, error).

    fields is [(name, kind, offset, size)]; error is a string when a boundary
    cannot be established."""
    off = 16
    out = []
    sm_len = 0
    for name, kind in layout:
        if kind == "u8":
            if off >= len(pdu):
                return out, "%s starts at %d past the end" % (name, off)
            size = 1
            if name == "sm_length":
                sm_len = pdu[off]
        elif kind == "cstr":
            end = pdu.find(b"\x00", off)
            if end < 0:
                return out, "no NUL for %s from offset %d" % (name, off)
            size = end - off + 1
        elif kind == "octets":
            size = sm_len
            if off + size > len(pdu):
                return out, "%s needs %d octets from %d, PDU ends at %d" % (name, size, off, len(pdu))
        else:
            return out, "unknown field kind %s" % kind
        out.append((name, kind, off, size))
        off += size
    return out, None


# ── pcap with a real handshake, then the PDU on 2775 ────────────────────
def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += int.from_bytes(data[i:i + 2], "big")
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def frame(payload, seq, ack, flags, reverse=False):
    cli = bytes([10, 0, 0, 1])
    srv = bytes([10, 0, 0, 2])
    src, dst = (srv, cli) if reverse else (cli, srv)
    sport, dport = (2775, 40000) if reverse else (40000, 2775)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 8192, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
    eth = bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00"
    return eth + ip + tcp + payload


def write_pcap(path, pdu):
    frames = [
        frame(b"", 1000, 0, 0x02),                      # SYN
        frame(b"", 5000, 1001, 0x12, reverse=True),     # SYN-ACK
        frame(b"", 1001, 5001, 0x10),                   # ACK
        frame(pdu, 1001, 5001, 0x18),                   # PSH-ACK carrying the PDU
    ]
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = 1700000000
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)


def dissect_verbose(path):
    r = subprocess.run([THS, "-r", path, "-d", "tcp.port==2775,smpp", "-V"],
                       text=True, capture_output=True)
    return r.stdout + r.stderr


def dissect_pdml(path):
    r = subprocess.run([THS, "-r", path, "-d", "tcp.port==2775,smpp", "-T", "pdml"],
                       text=True, capture_output=True)
    try:
        root = ET.fromstring(r.stdout)
    except ET.ParseError as exc:
        return None, "pdml did not parse: %s" % exc
    fields = {}
    for f in root.iter("field"):
        name = f.get("name") or ""
        fields.setdefault(name, []).append({
            "pos": int(f.get("pos") or -1),
            "size": int(f.get("size") or -1),
            "value": f.get("value") or "",
            "show": f.get("show") or "",
        })
    return fields, None


def verify_pdu(tag, pdu_hex, layout, expect_op, expect_lines, response=False):
    """One built PDU: module parse, independent spine, then tshark."""
    pdu = bytes.fromhex(pdu_hex)
    # 1. the module's own parse must claim success and agree with the spine.
    r = run("--smpp-parse", pdu_hex)
    check("module-parse:%s:rc" % tag, r.returncode == 0, "rc=%d stderr=%s" % (r.returncode, r.stderr.strip()[:160]))
    prow = rows(r.stdout)
    check("module-parse:%s:parsed" % tag, prow.get("parsed") == ["yes"], prow.get("parsed"))
    check("module-parse:%s:length" % tag, prow.get("command_length") == [str(len(pdu))], prow.get("command_length"))
    mfields = parse_fields(r.stdout)
    # 2. the spine, computed here from the PDU definitions alone.
    check("length-field:%s" % tag, int.from_bytes(pdu[0:4], "big") == len(pdu),
          "field=%d size=%d" % (int.from_bytes(pdu[0:4], "big"), len(pdu)))
    fields, err = spine(layout, pdu)
    if err:
        bad("spine:%s" % tag, err)
        return
    for name, kind, off, size in fields:
        if kind == "cstr":
            check("nul-at-boundary:%s:%s" % (tag, name),
                  size >= 1 and pdu[off + size - 1] == 0, "offset=%d size=%d" % (off, size))
        m = [f for f in mfields if f["name"] == name]
        check("module-offset:%s:%s" % (tag, name),
              len(m) == 1 and m[0]["off"] == off and len(bytes.fromhex(m[0]["hex"])) == size,
              "module=%s want=%d/%d" % ([(f["off"], len(bytes.fromhex(f["hex"]))) for f in m], off, size))
    consumed = 16 + sum(s for _, _, _, s in fields)
    check("spine-consumed:%s" % tag, consumed == len(pdu), "consumed=%d size=%d" % (consumed, len(pdu)))
    # 3. tshark, over a capture with the handshake in front of the payload.
    path = os.path.join(TMP, "%s.pcap" % tag)
    write_pcap(path, pdu)
    verbose = dissect_verbose(path)
    check("tshark-names-smpp:%s" % tag, "Short Message Peer to Peer" in verbose,
          "no SMPP dissector output for the frame")
    check("tshark-operation:%s" % tag, expect_op in verbose, "want %r" % expect_op)
    for needle in expect_lines:
        check("tshark-field:%s:%s" % (tag, needle.split(":")[0]), needle in verbose, "want %r" % needle)
    check("tshark-not-malformed:%s" % tag, "Malformed Packet" not in verbose, "tshark reported malformed")
    pdml, perr = dissect_pdml(path)
    if perr:
        bad("tshark-pdml:%s" % tag, perr)
        return
    base = pdml.get("smpp.command_length", [{}])[0].get("pos", -1)
    hdr = pdml.get("smpp.command_length", [])
    check("tshark-length-octets:%s" % tag,
          len(hdr) == 1 and hdr[0]["size"] == 4 and hdr[0]["value"] == pdu[0:4].hex(),
          hdr)
    for name, kind, off, size in fields:
        tname = TSHARK_FIELD.get(name)
        if not tname:
            continue
        got = pdml.get(tname, [])
        if not got and name in MAY_BE_ABSENT:
            continue
        check("tshark-offset:%s:%s" % (tag, name),
              len(got) >= 1 and got[0]["pos"] - base == off and got[0]["size"] == size,
              "tshark=%s want=%d/%d" % ([(g["pos"] - base, g["size"]) for g in got], off, size))
        if kind == "cstr" and got:
            check("tshark-nul:%s:%s" % (tag, name), got[0]["value"].endswith("00"),
                  "value=%s" % got[0]["value"])
    # command id and sequence number as the dissector reads them back.
    check("tshark-command-id:%s" % tag,
          pdml.get("smpp.command_id", [{}])[0].get("value") == pdu[4:8].hex(),
          pdml.get("smpp.command_id", [{}])[0].get("value"))
    check("tshark-sequence:%s" % tag,
          pdml.get("smpp.sequence_number", [{}])[0].get("value") == pdu[12:16].hex(),
          pdml.get("smpp.sequence_number", [{}])[0].get("value"))
    if response:
        check("tshark-status:%s" % tag,
              pdml.get("smpp.command_status", [{}])[0].get("value") == pdu[8:12].hex(),
              pdml.get("smpp.command_status", [{}])[0].get("value"))


def verify_refusal(tag, rc, out, err, want_rc, want_words):
    check("refuse-rc:%s" % tag, rc == want_rc, "rc=%d want=%d" % (rc, want_rc))
    lines = err.splitlines()
    for word in want_words:
        check("refuse-word:%s:%s" % (tag, word), any(l.startswith(word + "\t") for l in lines),
              "stderr=%r" % err.strip()[:200])
    check("refuse-no-success:%s" % tag,
          "built\tyes" not in out and "parsed\tyes" not in out, "stdout carried a success row")


# ── 0. the dissector has to be there, and it has to know these ids ──────
version = subprocess.run([THS, "-v"], text=True, capture_output=True).stdout.splitlines()
version = version[0] if version else "tshark (version unknown)"
gfields = subprocess.run([THS, "-G", "fields"], text=True, capture_output=True).stdout
if "smpp.command_id" not in gfields:
    print("SKIP\t%s in PATH has no SMPP dissector (smpp.command_id absent from -G fields)" % version)
    sys.exit(2)

gvalues = subprocess.run([THS, "-G", "values"], text=True, capture_output=True).stdout
tshark_ids = {}
for line in gvalues.splitlines():
    p = line.split("\t")
    if len(p) >= 4 and p[1] == "smpp.command_id":
        tshark_ids[int(p[2], 16)] = p[3]


def norm(s):
    return "".join(ch for ch in s.lower() if ch.isalnum())


for name, cid, want_name in [
    ("submit_sm", 0x00000004, "Submit_sm"),
    ("deliver_sm", 0x00000005, "Deliver_sm"),
    ("bind_transceiver", 0x00000009, "Bind_transceiver"),
    ("submit_sm_resp", 0x80000004, "Submit_sm - resp"),
    ("deliver_sm_resp", 0x80000005, "Deliver_sm - resp"),
    ("bind_transceiver_resp", 0x80000009, "Bind_transceiver - resp"),
    ("generic_nack", 0x80000000, "Generic_nack - resp"),
]:
    r = run("--smpp-pdu", name)
    rows_d = rows(r.stdout)
    check("pdu-id:%s" % name, rows_d.get("command_id") == ["%08x" % cid], rows_d.get("command_id"))
    check("pdu-id-vs-tshark:%s" % name,
          tshark_ids.get(cid) is not None and norm(tshark_ids[cid]) == norm(name),
          "tshark=%r module=%r" % (tshark_ids.get(cid), name))
    if want_name in tshark_ids.values():
        ok("pdu-name-tshark:%s" % name, tshark_ids[cid])

# ── 1. build the three request PDUs and check them ──────────────────────
built = {}
b = run("--smpp-build", "submit_sm", "--src", "15551234567", "--dst", "15559876543",
        "--msg", "48656c6c6f", "--dcs", "00", "--rd", "01", "--seq", "1")
check("build-submit:rc", b.returncode == 0, b.stderr.strip()[:200])
built["submit_sm"] = rows(b.stdout).get("hex", [""])[0]
verify_pdu("submit_sm", built["submit_sm"], LAYOUT_SUBMIT, "Command: Submit_sm",
           ["Originator address: 15551234567",
            "Recipient address: 15559876543",
            "Message bytes: 48656c6c6f",
            "Service type: (Default)",
            "Data coding: SMSC default alphabet",
            "Delivery receipt: Delivery receipt requested"])

b = run("--smpp-build", "deliver_sm", "--src", "15551234567", "--dst", "15559876543",
        "--msg", "48656c6c6f", "--dcs", "00", "--rd", "01", "--seq", "3")
check("build-deliver:rc", b.returncode == 0, b.stderr.strip()[:200])
built["deliver_sm"] = rows(b.stdout).get("hex", [""])[0]
verify_pdu("deliver_sm", built["deliver_sm"], LAYOUT_SUBMIT, "Command: Deliver_sm",
           ["Originator address: 15551234567",
            "Recipient address: 15559876543",
            "Message bytes: 48656c6c6f"])

b = run("--smpp-build", "bind_transceiver", "--system-id", "smppclient1",
        "--password", "password", "--seq", "2")
check("build-bind:rc", b.returncode == 0, b.stderr.strip()[:200])
built["bind_transceiver"] = rows(b.stdout).get("hex", [""])[0]
verify_pdu("bind_transceiver", built["bind_transceiver"], LAYOUT_BIND,
           "Command: Bind_transceiver",
           ["System ID: smppclient1", "Password: password", "Version (if): 3.4",
            "Address: NULL"])

# ── 2. the two responses the tree builds ────────────────────────────────
r = run("--smpp-response", built["bind_transceiver"], "--system-id", "SMSC01")
check("build-bind-resp:rc", r.returncode == 0, r.stderr.strip()[:200])
verify_pdu("bind_transceiver_resp", rows(r.stdout).get("hex", [""])[0], LAYOUT_BIND_RESP,
           "Command: Bind_transceiver - resp",
           ["System ID: SMSC01", "Result: Ok (0x00000000)"], response=True)

r = run("--smpp-response", built["submit_sm"])
check("build-submit-resp:rc", r.returncode == 0, r.stderr.strip()[:200])
verify_pdu("submit_sm_resp", rows(r.stdout).get("hex", [""])[0], LAYOUT_MSG_RESP,
           "Command: Submit_sm - resp", ['Status: "Ok"'], response=True)

# ── 3. negative control: a length field that does not match the body ─────
good = bytes.fromhex(built["submit_sm"])
bad_pdu = b"\x00\x00\x00\x10" + good[4:]
badpath = os.path.join(TMP, "bad-length.pcap")
write_pcap(badpath, bad_pdu)
v = dissect_verbose(badpath)
check("negation:tshark-dissects", "Short Message Peer to Peer" in v, "no SMPP output at all")
check("negation:tshark-malformed", "Malformed Packet: SMPP" in v, "tshark did not call it malformed")
r = run("--smpp-parse", bad_pdu.hex())
check("negation:module-rc", r.returncode == 1, "rc=%d" % r.returncode)
verify_refusal("negation:module", r.returncode, r.stdout, r.stderr, 1, ["ERROR", "WHY"])
check("negation:module-length-rows",
      rows(r.stdout).get("command_length") == ["16"] and
      rows(r.stdout).get("command_length_actual") == [str(len(bad_pdu))],
      rows(r.stdout))
r = run("--smpp-parse", (b"\x00\x00\x00\x11" + good[4:16] + b"\x00" + b"41").hex())
verify_refusal("negation:no-nul", r.returncode, r.stdout, r.stderr, 1, ["ERROR", "WHY"])

# ── 4. the refusals, so a PASS also means nothing was invented ──────────
r = run("--smpp-build", "submit_sm", "--src", "1", "--dst", "2", "--tlv")
verify_refusal("refuse-tlv", r.returncode, r.stdout, r.stderr, 2, ["ERROR", "WHY"])
r = run("--smpp-build", "submit_multi")
verify_refusal("refuse-unbuilt-pdu", r.returncode, r.stdout, r.stderr, 2, ["ERROR", "WHY"])
r = run("--smpp-build", "submit_sm", "--src", "1", "--dst", "2", "--msg", "00" * 255)
verify_refusal("refuse-oversize-message", r.returncode, r.stdout, r.stderr, 1, ["ERROR", "WHY"])
r = run("--smpp-build", "bind_transceiver", "--system-id", "", "--password", "x")
verify_refusal("refuse-empty-system-id", r.returncode, r.stdout, r.stderr, 2, ["ERROR", "WHY"])
r = run("--smpp-response", "00000010000000030000000000000001")
verify_refusal("refuse-query-sm-resp", r.returncode, r.stdout, r.stderr, 1, ["ERROR", "WHY"])
r = run("--smpp-response", built["submit_sm"], "--status", "0x100")
check("status-outside-octet-name", r.returncode == 0 and
      rows(r.stdout).get("command_status_name") == ["unassigned"], rows(r.stdout))

# ── 5. command id / direction table for ids not in the built set ─────────
for name, cid in [("unbind", 0x00000006), ("enquire_link", 0x00000015),
                  ("alert_notification", 0x00000102), ("outbind", 0x0000000B)]:
    r = run("--smpp-pdu", name)
    check("pdu-table:%s" % name, rows(r.stdout).get("command_id") == ["%08x" % cid],
          rows(r.stdout).get("command_id"))
    check("pdu-table-vs-tshark:%s" % name,
          tshark_ids.get(cid) is not None and norm(tshark_ids[cid]) == norm(name),
          "tshark=%r" % tshark_ids.get(cid))

print("CHECKS\t%d" % checks)
if fails:
    print("RESULT\tFAIL(%d)" % fails)
    sys.exit(1)
print("RESULT\tPASS")
print("ORACLE\t%s, port 2775 bound to smpp with -d" % version)
sys.exit(0)
SMPP_ORACLE
rc=$?
case "$rc" in
    0|1|2) exit "$rc" ;;
    *)     exit 1 ;;
esac
