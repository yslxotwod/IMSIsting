#!/usr/bin/env python3
"""Check the NAS messages `32_nas_signaling --build-nas` produces.

The claim under test is not "the module agrees with itself". It is that a
message this tree builds is the message a third-party implementation reads it
as. So every vector is built by the module's own CLI, wrapped in a GSMTAP LTE
NAS packet, and handed to `tshark`; what tshark decodes is compared with the
message name and IE values the module said it was building.

Exit codes: 0 all checked vectors agree, 1 a mismatch, 2 tshark is absent (a
skip, and the summary says SKIP -- a suite that reports PASS because its oracle
is missing is the failure this script exists to prevent).

The 5GS vectors cannot be checked this way: GSMTAP has no 5G-NAS payload type in
Wireshark 4.2.2 and `nas-5gs` cannot be bound to a UDP port, so the only route
would be a fake SCTP/NGAP stack. They are reported UNVERIFIED with that reason
rather than passed or silently dropped -- the 5GS message type numbers in the
module were read from tshark's own value table, which is a weaker claim than a
decoded message, and the difference is printed.
"""

import os
import struct
import subprocess
import sys
import tempfile

MODULE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "modules", "32_nas_signaling.sh")

# case id, generation, message, extra argv, expected fields
#   msg_hex   : nas-eps.nas_msg_emm_type
#   cause     : nas-eps.emm.cause
#   id_type   : nas-eps.emm.id_type2
#   ksi       : nas-eps.emm.nas_key_set_id
#   malformed : "yes" if tshark must report the packet as malformed
RAND = "000102030405060708090a0b0c0d0e0f"

CASES = [
    ("eps-attach-reject", "eps", "attach-reject", ["--cause", "15"],
     {"msg_hex": "0x44", "cause": "15"}),
    ("eps-tau-reject", "eps", "tau-reject", ["--cause", "12"],
     {"msg_hex": "0x4b", "cause": "12"}),
    ("eps-service-reject", "eps", "service-reject", ["--cause", "22"],
     {"msg_hex": "0x4e", "cause": "22"}),
    ("eps-identity-imsi", "eps", "identity-request", ["--identity", "imsi"],
     {"msg_hex": "0x55", "id_type": "1"}),
    ("eps-identity-imeisv", "eps", "identity-request", ["--identity", "imeisv"],
     {"msg_hex": "0x55", "id_type": "3"}),
    ("eps-auth-request", "eps", "auth-request",
     ["--rand", RAND, "--ksi", "3"],
     {"msg_hex": "0x52", "ksi": "3"}),
    ("eps-auth-reject", "eps", "auth-reject", [],
     {"msg_hex": "0x54"}),
    ("eps-auth-failure", "eps", "auth-failure", ["--cause", "21"],
     {"msg_hex": "0x5c", "cause": "21"}),
    ("eps-smc-reject", "eps", "security-mode-reject", ["--cause", "23"],
     {"msg_hex": "0x5f", "cause": "23"}),
    ("eps-smc", "eps", "security-mode-command",
     ["--algorithms", "2", "2", "--ksi", "3"],
     {"msg_hex": "0x5d", "ksi": "3"}),
]

UNVERIFIED_5GS = [
    "5gs-registration-reject", "5gs-service-reject", "5gs-identity-request",
    "5gs-auth-request", "5gs-auth-reject", "5gs-auth-failure",
    "5gs-security-mode-command", "5gs-security-mode-reject",
]


def build(case_id, gen, msg, extra):
    argv = ["bash", MODULE, "--build-nas", gen, msg] + extra
    r = subprocess.run(argv, capture_output=True, text=True)
    rows = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            rows[parts[0]] = parts[1]
    return rows, r.returncode, r.stderr


def gsmtap_packet(nas_hex):
    nas = bytes.fromhex(nas_hex)
    # GSMTAP header: version|hdr_len, type 18 (LTE NAS), timeslot, arfcn,
    # signal, snr, frame number, sub_type, antenna, sub_slot, reserved.
    hdr = bytes([0x02, 0x04, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    payload = hdr + nas
    ulen = 8 + len(payload)
    ip = (bytes([0x45, 0x00]) + struct.pack(">H", 20 + ulen)
          + bytes([0, 1, 0, 0, 64, 17, 0, 0])
          + bytes([127, 0, 0, 1, 127, 0, 0, 1]))
    udp = struct.pack(">HHHH", 4729, 4729, ulen, 0)
    return bytes(12) + bytes([0x08, 0x00]) + ip + udp + payload


def write_pcap(path, packet):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1, 0, len(packet), len(packet)))
        f.write(packet)


FIELDS = ["gsmtap.type", "nas-eps.nas_msg_emm_type", "nas-eps.emm.cause",
          "nas-eps.emm.id_type2", "nas-eps.emm.nas_key_set_id"]


# The keys a case may assert on, mapped to the tshark field that carries them.
WANT_FIELDS = {
    "msg_hex": "nas-eps.nas_msg_emm_type",
    "cause": "nas-eps.emm.cause",
    "id_type": "nas-eps.emm.id_type2",
    "ksi": "nas-eps.emm.nas_key_set_id",
}


def decode(pcap):
    r = subprocess.run(
        ["tshark", "-r", pcap, "-T", "fields"] +
        sum((["-e", f] for f in FIELDS), []),
        capture_output=True, text=True)
    values = {}
    line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
    for name, val in zip(FIELDS, (line.split("\t") + [""] * len(FIELDS))):
        values[name] = val
    verbose = subprocess.run(["tshark", "-r", pcap, "-V"],
                             capture_output=True, text=True).stdout
    values["malformed"] = "yes" if "Malformed Packet" in verbose else "no"
    return values


def main():
    if not subprocess.run(["which", "tshark"], capture_output=True).returncode == 0:
        print("SKIP\tno tshark on PATH; the NAS oracle cannot run")
        return 2
    if not os.path.exists(MODULE):
        print("FAIL\tmodule not found: %s" % MODULE)
        return 1

    bad = 0
    checked = 0
    for case_id, gen, msg, extra, want in CASES:
        rows, rc, stderr = build(case_id, gen, msg, extra)
        if rc != 0 or "hex" not in rows:
            print("FAIL\t%s\tbuild rc=%d %s" % (case_id, rc, stderr.strip()[:80]))
            bad += 1
            continue
        pcap = tempfile.mktemp(suffix=".pcap")
        write_pcap(pcap, gsmtap_packet(rows["hex"]))
        got = decode(pcap)
        os.unlink(pcap)
        problems = []
        if got["gsmtap.type"] != "18":
            problems.append("gsmtap.type=%s" % got["gsmtap.type"])
        for key, want_value in want.items():
            field = WANT_FIELDS[key]
            have = got.get(field, "")
            if have != want_value:
                problems.append("%s want=%s got=%s" % (key, want_value, have))
        # The module must not claim the message was sent.
        if rows.get("sent") != "0":
            problems.append("sent=%s" % rows.get("sent"))
        checked += 1
        if problems:
            bad += 1
            print("FAIL\t%s\t%s\tdecoded=%s" %
                  (case_id, "; ".join(problems), rows["hex"]))
        else:
            print("ok\t%s\t%s\t%s" %
                  (case_id, rows["hex"],
                   ", ".join("%s=%s" % (k, got[WANT_FIELDS[k]]) for k in sorted(want))))

    for case_id in UNVERIFIED_5GS:
        print("unverified\t%s\tno GSMTAP payload type for 5G NAS in Wireshark "
              "4.2.2, so the message type numbers are taken from tshark's own "
              "value table rather than from a decoded message" % case_id)

    print("checked\t%d of %d EPS vectors, %d unverified 5GS vectors"
          % (checked, len(CASES), len(UNVERIFIED_5GS)))
    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
