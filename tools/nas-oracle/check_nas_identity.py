#!/usr/bin/env python3
"""Referee for tools/nas_identity.py: tshark and pycrate, not the tool itself.

Two referees, two different questions:

* **pycrate** answers "are these octets the message you say they are?"  It is
  asked to encode the same message and the octets are compared, so a wrong
  length or a shifted identity-type bit fails here even when the tool agrees
  with itself.
* **tshark** answers "does a dissector read this as an IMSI?"  It is given a
  capture with the message inside an S1AP InitialUEMessage on SCTP, and its
  identity-type field is compared with the tool's reading.

The digit field needs one documented adjustment.  tshark prints its ``IMSI:``
field with the spare nibble of the identity octet as a leading digit (a NAS
identity octet of ``0x09`` has a spare high nibble of 0), so a 15-digit IMSI
appears there as 16 digits with a ``0`` in front.  The oracle removes exactly
that one character and says so, instead of quietly comparing the wrong strings.

Run it with the oracle interpreter (pycrate lives there):

    /home/ysl/.lte-oracles/venv/bin/python tools/nas-oracle/check_nas_identity.py
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOL = os.path.join(ROOT, "tools", "nas_identity.py")
S1AP = os.path.join(ROOT, "tools", "s1ap_asn1.py")
TSHARK = "/usr/bin/tshark"

# Fixtures: the octets are written here, not imported from the tool, so the
# oracle has its own copy of the layout claim.
#
#   attach request, IMSI 208010123456789 (odd count, so the last nibble is 0xf)
#   octet 3 is attach type/KSI, octet 4 is the EPS mobile identity length,
#   octet 5 is type-of-identity (0x09 = IMSI + odd), then the BCD digits.
CASES = [
    {
        "name": "attach-imsi-odd",
        "nas": "074101" "09" "09" "02080121436587f9",
        "identity_kind": "imsi",
        "identity": "208010123456789",
        "mcc": "208",
        "mnc_2digit": "01",
        "tshark_type": "IMSI",
        "pycrate": ("attach", "208010123456789"),
    },
    {
        "name": "attach-imsi-even",
        "nas": "074101" "08" "01" "02080121436587",
        "identity_kind": "imsi",
        "identity": "20801012345678",
        "mcc": "208",
        "mnc_2digit": "01",
        "tshark_type": "IMSI",
        "pycrate": ("attach", "20801012345678"),
    },
    {
        "name": "attach-guti",
        "nas": "074101" "0b" "06" "00f110" "0001" "02" "0a0b0c0d",
        "identity_kind": "guti",
        "identity": "mmegi=1 mme_code=2 m-tmsi=0x0a0b0c0d",
        "mcc": "001",
        "mnc_2digit": "01",
        "tshark_type": "GUTI",
        "pycrate": None,
    },
    {
        "name": "identity-response-imsi",
        "nas": "0756" "08" "01" "02080121436587",
        "identity_kind": "imsi",
        "identity": "20801012345678",
        "mcc": "208",
        "mnc_2digit": "01",
        "tshark_type": "IMSI",
        "pycrate": ("response", "20801012345678"),
    },
]

# Defects that must be caught.  Each mutates the FIXTURE, so the referee is the
# thing under test: if a mutation still agrees with tshark and pycrate, the
# comparison is not doing its job.
NEGCTL = [
    ("swapped-nibbles", "attach-imsi-odd",
     lambda h: h[:10] + "020180 12436587f9".replace(" ", "")),
    ("length-counts-digits-only", "attach-imsi-odd",
     lambda h: h[:8] + "08" + h[10:]),
    ("type-bits-shifted", "attach-imsi-odd",
     lambda h: h[:8] + "02" + h[10:]),
    ("drop-odd-bit", "attach-imsi-odd",
     lambda h: h[:10] + "01" + h[12:]),
]


def run(cmd: list[str], stdin: str | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def tool_rows(nas: str) -> dict[str, str]:
    rc, out, _err = run([sys.executable, TOOL, "decode", nas])
    rows: dict[str, str] = {}
    for line in out.splitlines():
        if "\t" in line:
            key, value = line.split("\t", 1)
            rows[key] = value
    rows["_rc"] = str(rc)
    return rows


# ── pycrate ─────────────────────────────────────────────────────────────
def pycrate_octets(kind: str, digits: str) -> tuple[str, str]:
    """(whole message, identity element) as pycrate encodes them.

    Only the element is compared: the two writers legitimately disagree about
    the bytes that FOLLOW the identity (pycrate fills the network-capability
    and ESM container with its defaults; this tree's fixtures stop at the
    identity), so comparing whole messages would compare two different
    decisions rather than the layout under test.
    """
    from pycrate_mobile.TS24301_EMM import EMMAttachRequest, EMMIdentityResponse

    def bcd(text: str) -> bytes:
        padded = text + ("f" if len(text) % 2 else "")
        return bytes(int(padded[i], 16) | (int(padded[i + 1], 16) << 4)
                     for i in range(0, len(padded), 2))

    first = 0x01 | (0x08 if len(digits) % 2 else 0x00)
    value = bytes([first]) + bcd(digits)

    if kind == "attach":
        msg = EMMAttachRequest()
        epsid = {ch._name: ch for ch in
                 {c._name: c for c in msg._content}["EPSID"]._content}
        epsid["V"]._val = value
        epsid["L"]._val = None
        octets = msg.to_bytes()
        # 07 41 <attach type> then the length/value element.
        return octets.hex(), octets[3:3 + 1 + len(value)].hex()

    if kind == "response":
        msg = EMMIdentityResponse()
        element = {ch._name: ch for ch in {c._name: c for c in msg._content}["ID"]._content}
        element["V"]._val = value
        element["L"]._val = None
        octets = msg.to_bytes()
        return octets.hex(), octets[2:].hex()

    raise ValueError("no pycrate builder for %r" % kind)


# ── tshark ──────────────────────────────────────────────────────────────
def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pcap(out: str, payload_hex: str, ppid: int = 18,
         sport: int = 36412, dport: int = 36412) -> None:
    payload = bytes.fromhex(payload_hex)
    chunk = (struct.pack("!BBH", 0, 0x03, 16 + len(payload)) +
             struct.pack("!IHHI", 1, 0, 0, ppid) + payload)
    sctp = struct.pack("!HHII", sport, dport, 0, 0) + chunk
    sctp = sctp[:8] + struct.pack("!I", _csum(sctp)) + sctp[12:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(sctp), 1, 0, 64, 132, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    frame = bytes.fromhex("0200000000020200000000010800") + ip + sctp
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 0, 0, len(frame), len(frame))
    with open(out, "wb") as handle:
        handle.write(header + record + frame)


def tshark_fields(nas: str, path: str) -> dict[str, str]:
    rc, out, _err = run([sys.executable, S1AP, "initial-ue",
                         "--mme-ue-id", "0x1", "--enb-ue-id", "0x2", "--nas", nas])
    if rc != 0:
        return {"_error": "s1ap wrapper refused the NAS: %s" % out.strip()}
    hex_octets = ""
    for line in out.splitlines():
        if line.startswith("hex\t"):
            hex_octets = line.split("\t", 1)[1]
    if not hex_octets:
        return {"_error": "s1ap wrapper printed no octets"}
    pcap(path, hex_octets)
    rc, text, _err = run([TSHARK, "-V", "-r", path])
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "Type of identity:" in line:
            fields["type"] = line.split("Type of identity:", 1)[1].strip()
        elif "Mobile identity - " in line:
            # An Identity Response prints the same element under a different
            # label: "Mobile identity - IMSI (1)".
            fields["type"] = line.split("Mobile identity - ", 1)[1].strip()
        elif line.startswith("IMSI:"):
            fields["imsi"] = line.split("IMSI:", 1)[1].strip()
        elif line.startswith("Mobile Country Code"):
            fields["mcc"] = line
    return fields


def main(argv: list[str]) -> int:
    negctl = "--negctl" in argv
    work = os.path.join(ROOT, "tmp", "nas-oracle")
    os.makedirs(work, exist_ok=True)

    cases = 0
    mismatches = 0
    notes: list[str] = []

    def verdict(name: str, ok: bool, detail: str) -> None:
        nonlocal cases, mismatches
        cases += 1
        print("ASSERTION\t%s\t%s\t%s" % (name, "AGREE" if ok else "MISMATCH", detail))
        if not ok:
            mismatches += 1

    for case in CASES:
        nas = case["nas"]
        rows = tool_rows(nas)
        verdict("%s-tool-runs" % case["name"], rows.get("_rc") == "0",
                "rc %s" % rows.get("_rc"))
        verdict("%s-kind" % case["name"],
                rows.get("identity_kind") == case["identity_kind"],
                "%s vs %s" % (rows.get("identity_kind"), case["identity_kind"]))
        verdict("%s-identity" % case["name"],
                rows.get("identity") == case["identity"],
                "%s vs %s" % (rows.get("identity"), case["identity"]))
        if case.get("mcc"):
            verdict("%s-mcc" % case["name"], rows.get("mcc") == case["mcc"],
                    "%s vs %s" % (rows.get("mcc"), case["mcc"]))
        if case.get("mnc_2digit"):
            verdict("%s-mnc" % case["name"],
                    rows.get("mnc_2digit") == case["mnc_2digit"],
                    "%s vs %s" % (rows.get("mnc_2digit"), case["mnc_2digit"]))

        fields = tshark_fields(nas, os.path.join(work, case["name"] + ".pcap"))
        if "_error" in fields:
            verdict("%s-tshark-reads" % case["name"], False, fields["_error"])
        else:
            got = fields.get("type", "")
            verdict("%s-tshark-type" % case["name"],
                    got.startswith(case["tshark_type"]),
                    "%r vs %r" % (got, case["tshark_type"]))
            if case["identity_kind"] == "imsi" and "imsi" in fields:
                sent = fields["imsi"]
                # The spare nibble of the identity octet (0 in these fixtures)
                # is printed by tshark as a leading digit; drop exactly one.
                trimmed = sent[1:] if sent.startswith("0") else sent
                verdict("%s-tshark-digits" % case["name"],
                        trimmed == case["identity"],
                        "%r (spare digit removed from %r)" % (trimmed, sent))

        if case["pycrate"] is not None:
            kind, digits = case["pycrate"]
            try:
                whole, element = pycrate_octets(kind, digits)
                verdict("%s-pycrate-octets" % case["name"], element in nas,
                        "pycrate element %s in fixture %s (whole message %s)"
                        % (element, nas, whole))
            except Exception as exc:          # noqa: BLE001 - reported, not raised
                verdict("%s-pycrate-octets" % case["name"], False,
                        "%s: %s" % (type(exc).__name__, exc))

    if negctl:
        caught = 0
        by_name = {c["name"]: c for c in CASES}
        for name, base, mutate in NEGCTL:
            case = by_name[base]
            broken = mutate(case["nas"])
            rows = tool_rows(broken)
            agreed = (rows.get("identity") == case["identity"] and
                      rows.get("identity_kind") == case["identity_kind"])
            fields = tshark_fields(broken, os.path.join(work, "neg-" + name + ".pcap"))
            tshark_ok = fields.get("type", "").startswith(case["tshark_type"])
            same = agreed and tshark_ok
            print("NEGCTL\t%s\t%s\t%s" % (name, "MISSED" if same else "CAUGHT",
                                          "tool %r tshark %r" %
                                          (rows.get("identity"),
                                           fields.get("type", "absent"))))
            if not same:
                caught += 1
        print("NEGCTL_RESULT\t%d/%d caught" % (caught, len(NEGCTL)))
        if caught != len(NEGCTL):
            mismatches += 1

    print("CASES\t%d" % cases)
    print("MISMATCHES\t%d" % mismatches)
    print("not-compared\tdecryption: a ciphered body has no identity to compare")
    print("RESULT\t%s" % ("AGREE" if mismatches == 0 else "DISAGREE"))
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
