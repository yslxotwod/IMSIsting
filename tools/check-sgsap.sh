#!/usr/bin/env bash
# tools/check-sgsap.sh — grade the SGsAP (TS 29.118) messages this tree builds
# with an outside implementation instead of with our own encoder.
#
# Each case asks the module for a message with `--sgsap-build`, wraps the hex it
# prints in Ethernet + IPv4 + SCTP (port 29118, PPID 0) in a libpcap file, and
# has tshark dissect it. A case passes only when
#   * the module's hex is the known-answer hex the standard and tshark agree on,
#     with one-octet IE length indicators (TS 29.118 §9.3a),
#   * tshark names the message type and the fields the module claims, and
#   * the IE rows the module prints match the octets it printed.
#
# There is also a negation control: the same frame with the message-type octet
# corrupted must NOT be reported as that SGsAP message. tshark keeps the SGsAP
# tree because it keys that on SCTP port 29118, so the honest claim is "no
# message type is recognised" — any known type coming back would be a failure.
#
# Exit: 0 pass, 1 fail, 2 skip (python3 or tshark missing). A skip is never a
# pass. Output is tab-separated on stdout; SKIP lines go to stderr like the
# other check-*.sh scripts.
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf 'SKIP\tno %s on PATH\n' "$PY" >&2
    exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
    printf 'SKIP\ttshark is not on PATH, so no outside implementation can decode the built messages\n' >&2
    exit 2
fi

"$PY" - "$ROOT" <<'PYCODE'
import struct
import subprocess
import sys
import tempfile
import os

ROOT = sys.argv[1]
MODULE = os.path.join(ROOT, "modules", "26_ss7_map.sh")
TSHARK_TIMEOUT = 120

# ── pcap: Ethernet + IPv4 + SCTP carrying one SGsAP message ──────────────
def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

def inet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def sctp(payload, sport=29118, dport=29118, ppid=0):
    data = (bytes([0x00, 0x03]) + struct.pack(">H", 16 + len(payload))
            + struct.pack(">IHHI", 1, 0, 0, ppid) + payload)
    hdr = struct.pack(">HHII", sport, dport, 1, 0)
    chunk = hdr[:8] + struct.pack("<I", crc32c(hdr[:8] + data)) + data
    return chunk

def ipv4(payload):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64,
                      132, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    hdr = hdr[:10] + struct.pack(">H", inet_checksum(hdr)) + hdr[12:]
    return hdr + payload

def ethernet(payload):
    return bytes.fromhex("00112233445566778899aabb") + b"\x08\x00" + payload

def write_pcap(path, sgsap):
    frame = ethernet(ipv4(sctp(sgsap)))
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
        f.write(frame)

# ── module driver ────────────────────────────────────────────────────────
def run(argv):
    return subprocess.run(["bash", MODULE] + argv, capture_output=True,
                          text=True, timeout=TSHARK_TIMEOUT)

def rows(stdout):
    out = []
    for line in stdout.splitlines():
        if "\t" in line:
            f, v = line.split("\t", 1)
            out.append((f, v))
    return out

def first(rs, key):
    for f, v in rs:
        if f == key:
            return v
    return ""

def all_of(rs, key):
    return [v for f, v in rs if f == key]

def tshark_verbose(path):
    return subprocess.run(["tshark", "-r", path, "-V"], capture_output=True,
                          text=True, timeout=TSHARK_TIMEOUT)

def tshark_fields(path, fields):
    args = ["tshark", "-r", path, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    r = subprocess.run(args, capture_output=True, text=True, timeout=TSHARK_TIMEOUT)
    return r.stdout.splitlines()

# ── known-answer vectors ─────────────────────────────────────────────────
# The hex below is decoded by tshark 4.2.2 as the named message with these
# fields; the same values are pinned in the module selftest. TS 29.118 §9.3a:
# IE = IEI (1 octet) + length indicator (ONE octet) + value.
MME = "066D6D65633031096D6D65676930303031036D6D6503657063066D6E63313530066D63633331300B336770706E6574776F726B036F7267"
VLR = "04766C7231066D6E63313530066D63633331300B336770706E6574776F726B036F7267"

VECTORS = [
    {
        "case": "location-update-request",
        "flags": ["--imsi", "310150123456789", "--lai", "310-150-1"],
        "msg_type": "0x09",
        "hex": "0901083901511032547698" + "0937" + MME + "0A0102" + "04051300510001",
        "ies": [
            (1, "01", "IMSI", 8, "3901511032547698"),
            (2, "09", "MME name", 55, MME),
            (3, "0A", "EPS location update type", 1, "02"),
            (4, "04", "Location area identifier", 5, "1300510001"),
        ],
        # tshark 4.2.2, -V on the frame: the message name, the length field of
        # the fixed-size MME name (TS 29.118 §9.4.13: 55 octets), the decoded
        # FQDN, and the location-update type and LAI it decodes from the value.
        "tree": [
            "SGsAP-LOCATION-UPDATE-REQUEST",
            "IMSI: 310150123456789",
            "Odd/even indication: Odd number of identity digits",
            "MME name - mmec01.mmegi0001.mme.epc.mnc150.mcc310.3gppnetwork.org",
            "Length: 55",
            "EPS location update type: Normal location update (2)",
            "Location Area Code (LAC): 0x0001 (1)",
        ],
    },
    {
        "case": "paging-request",
        "flags": ["--imsi", "310150123456789", "--service-indicator", "cs",
                  "--lai", "310-150-1"],
        "msg_type": "0x01",
        "hex": "0101083901511032547698" + "0223" + VLR + "200101" + "04051300510001",
        "ies": [
            (1, "01", "IMSI", 8, "3901511032547698"),
            (2, "02", "VLR name", 35, VLR),
            (3, "20", "Service indicator", 1, "01"),
            (4, "04", "Location area identifier", 5, "1300510001"),
        ],
        "tree": [
            "SGsAP-PAGING-REQUEST",
            "VLR name - vlr1.mnc150.mcc310.3gppnetwork.org",
            "Length: 35",
            "Service indicator - CS call indicator",
        ],
    },
    {
        "case": "downlink-unitdata",
        "flags": ["--imsi", "310150123456789", "--nas", "0901020200"],
        "msg_type": "0x07",
        "hex": "0701083901511032547698" + "1605" + "0901020200",
        "ies": [
            (1, "01", "IMSI", 8, "3901511032547698"),
            (2, "16", "NAS message container", 5, "0901020200"),
        ],
        "tree": [
            "SGsAP-DOWNLINK-UNITDATA",
            "NAS message container",
            "Length: 5",
            "CP-DATA",
            "Protocol Discriminator: SMS messages (9)",
        ],
    },
    {
        "case": "service-request",
        "flags": ["--imsi", "310150123456789", "--service-indicator", "cs",
                  "--tai", "310-150-1", "--emm-mode", "connected"],
        "msg_type": "0x06",
        "hex": "0601083901511032547698" + "200101" + "23051300510001" + "250101",
        "ies": [
            (1, "01", "IMSI", 8, "3901511032547698"),
            (2, "20", "Service indicator", 1, "01"),
            (3, "23", "Tracking area identity", 5, "1300510001"),
            (4, "25", "UE EMM mode", 1, "01"),
        ],
        "tree": [
            "SGsAP-SERVICE-REQUEST",
            "Service indicator - CS call indicator",
            "Tracking area code(TAC): 1",
            "UE EMM mode: EMM-CONNECTED (1)",
        ],
    },
]

def main():
    problems = []
    cases = 0
    tmp = tempfile.mkdtemp(prefix="check-sgsap.")
    try:
        for vec in VECTORS:
            cases += 1
            case = vec["case"]
            r = run(["--sgsap-build", case] + vec["flags"])
            if r.returncode != 0:
                msg = r.stderr.strip().splitlines()[0] if r.stderr.strip() else "no ERROR line"
                problems.append(f"{case}: module exited {r.returncode}: {msg}")
                print(f"CASE\t{case}\tFAIL\tmodule refused the build")
                continue
            rs = rows(r.stdout)
            got_hex = first(rs, "hex").upper()
            got_type = first(rs, "message_type")
            octets = first(rs, "octets")
            if got_hex != vec["hex"]:
                problems.append(f"{case}: hex {got_hex} is not the known answer {vec['hex']}")
            if got_type != vec["msg_type"]:
                problems.append(f"{case}: message_type {got_type} is not {vec['msg_type']}")
            if str(len(vec["hex"]) // 2) != octets:
                problems.append(f"{case}: octets {octets} does not match the hex length")

            # The IE rows must add up to the message: 1 type octet, then
            # IEI + 1-octet length + value per row.
            ie_rows = all_of(rs, "ie")
            if len(ie_rows) != len(vec["ies"]):
                problems.append(f"{case}: {len(ie_rows)} ie rows for {len(vec['ies'])} IEs")
            total = 1
            for expected in vec["ies"]:
                idx, iei, name, vlen, vhex = expected
                total += 2 + vlen
            if total != int(octets or 0):
                problems.append(f"{case}: IE rows and type octet add up to {total}, hex says {octets}")
            for pos, expected in enumerate(vec["ies"], start=1):
                if pos > len(ie_rows):
                    problems.append(f"{case}: missing ie row {pos}")
                    continue
                parts = ie_rows[pos - 1].split("\t")
                if len(parts) != 5:
                    problems.append(f"{case}: ie row {pos} has {len(parts)} columns: {ie_rows[pos - 1]}")
                    continue
                idxi, iei, name, got_len, got_val = parts
                _, want_iei, want_name, want_len, want_val = expected
                if idxi != str(pos):
                    problems.append(f"{case}: ie row {pos} is numbered {idxi}")
                if (iei.upper(), name, got_len, got_val.upper()) != (want_iei, want_name, str(want_len), want_val):
                    problems.append(f"{case}: ie row {pos} is {iei} {name} {got_len} {got_val}, "
                                    f"want {want_iei} {want_name} {want_len} {want_val}")

            # Cross-check the built hex with tshark.
            path = os.path.join(tmp, case + ".pcap")
            write_pcap(path, bytes.fromhex(got_hex))
            v = tshark_verbose(path)
            if v.returncode != 0:
                problems.append(f"{case}: tshark exited {v.returncode}: {v.stderr.strip()[:200]}")
            vout = v.stdout
            if "SGs Application Part (SGsAP)" not in vout:
                problems.append(f"{case}: tshark did not dissect the frame as SGsAP")
            for want in vec["tree"]:
                if want not in vout:
                    problems.append(f"{case}: tshark -V never says {want!r}")
            fields = tshark_fields(path, ["sgsap.msg_type"])
            got_field = fields[0].strip() if fields else ""
            if got_field != vec["msg_type"]:
                problems.append(f"{case}: -e sgsap.msg_type says {got_field!r}, want {vec['msg_type']}")
            print(f"CASE\t{case}\tPASS\t{got_type} {octets} octets, tshark names the message and its fields")

        # ── negation control: corrupted message-type octet ──────────────
        base = VECTORS[0]["hex"]
        neg = "00" + base[2:]
        path = os.path.join(tmp, "negctl.pcap")
        write_pcap(path, bytes.fromhex(neg))
        v = tshark_verbose(path)
        vout = v.stdout
        fields = tshark_fields(path, ["sgsap.msg_type", "sgsap.unknown_msg"])
        line = fields[0] if fields else ""
        parts = line.split("\t") if line else []
        neg_type = parts[0].strip() if len(parts) > 0 else ""
        neg_unknown = parts[1].strip() if len(parts) > 1 else ""
        neg_ok = True
        if "SGsAP-LOCATION-UPDATE-REQUEST" in vout:
            neg_ok = False
            problems.append("negctl: a 0x00 type octet was still read as SGsAP-LOCATION-UPDATE-REQUEST")
        if neg_type:
            neg_ok = False
            problems.append(f"negctl: -e sgsap.msg_type still reported {neg_type!r} for type octet 0x00")
        if neg_unknown != "0x00":
            neg_ok = False
            problems.append(f"negctl: tshark reported unknown_msg {neg_unknown!r}, want 0x00")
        if "Unknown message: 0x00" not in vout:
            neg_ok = False
            problems.append("negctl: tshark -V does not mark the corrupted message type as unknown")
        print(f"NEGCTL\t{'PASS' if neg_ok else 'FAIL'}\tcorrupted type octet 0x00 is not a known SGsAP message")
    finally:
        for name in os.listdir(tmp):
            os.unlink(os.path.join(tmp, name))
        os.rmdir(tmp)

    print(f"CASES\t{cases}")
    print(f"MISMATCHES\t{len(problems)}")
    for p in problems:
        print(f"MISMATCH\t{p}")
    ok = not problems
    print(f"RESULT\t{'PASS' if ok else 'FAIL(%d)' % len(problems)}")
    print("NOTE\ttshark 4.2.2 dissected every frame on SCTP port 29118 with PPID 0; "
          "no frame here is decoded by this tree's own encoder")
    return 0 if ok else 1

sys.exit(main())
PYCODE
rc=$?
case "$rc" in
    0|1|2) exit "$rc" ;;
    *) exit 1 ;;
esac
