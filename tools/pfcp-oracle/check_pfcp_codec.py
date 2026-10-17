#!/usr/bin/env python3
"""PFCP codec check against the clauses and pycrate.

modules/13_nr_core.sh reads PFCP off the N4/Sxb reference points, and a PFCP
message is where a 5G core tells the user plane what to do with a subscriber's
traffic: a wrong IE number names a forwarding rule as a QoS rule, and a wrong
message type turns a session modification into a session establishment. So the
module is checked against the clause statement, not against itself.

What the clause says (ETSI TS 129 244 V15.8.0):

  §7.2.2.1  The PFCP header is the Version (bits 6-8), Spare (bits 3-5),
            MP (bit 2) and S (bit 1) in octet 1, the Message Type in octet 2,
            the Message Length in octets 3-4 -- "the length of the PFCP
            message in octets, excluding the first 4 octets" -- then the SEID
            (8 octets, only when S=1), the Sequence Number (3 octets) and one
            octet that holds the Message Priority in its high nibble when MP=1
            and spare (zero) otherwise.
  §7.2.2.2  A node related message has S=0 and no SEID; its last header octet
            is spare, so MP is zero there.
  §7.2.2.3  A session related message has S=1 and carries the SEID.
  Table 7.3-1  Message type values: 1-15 node related, 50-57 session related,
            16-49 and 58-255 for future use, 0 reserved.
  §8.1.2    An IE is a 2-octet Type, a 2-octet Length, then the Value. Bit 8
            of the first Type octet is the V flag: the remaining 15 bits are
            the IE type, and when V=1 the value begins with the 2-octet
            Enterprise ID and the Length counts it.
  Table 8.1.2-1  The IE type registry.
  §7.5      The grouped IEs: their value is itself a sequence of IEs, which
            the table reference marks (Table 7.5.2.2-1 and its siblings); the
            same holds for Application ID's PFDs (Table 7.4.3.1-2).

pycrate's TS29244_PFCP decoder is the second implementation: it is given the
same frames and its header fields and top-level IE sequence are compared with
what this check's own statement says.

A defect put back into a scratch copy of the module must make this fail:
  * an IE name moved back to the number its neighbour had
  * the Message Length counted from the start of the frame
  * the S flag ignored for a session related message
  * a vendor specific IE's Enterprise ID left in its value

usage: check_pfcp_codec.py [--module PATH] [--negctl] [--verbose] [--only LIST]
"""
import argparse
import os
import subprocess
import sys
import tempfile

MODULE = "/home/ysl/IMSIsting/modules/13_nr_core.sh"

MSG_TYPES = {
    1: 'Heartbeat Request',
    2: 'Heartbeat Response',
    3: 'PFD Management Request',
    4: 'PFD Management Response',
    5: 'Association Setup Request',
    6: 'Association Setup Response',
    7: 'Association Update Request',
    8: 'Association Update Response',
    9: 'Association Release Request',
    10: 'Association Release Response',
    11: 'Version Not Supported Response',
    12: 'Node Report Request',
    13: 'Node Report Response',
    14: 'Session Set Deletion Request',
    15: 'Session Set Deletion Response',
    50: 'Session Establishment Request',
    51: 'Session Establishment Response',
    52: 'Session Modification Request',
    53: 'Session Modification Response',
    54: 'Session Deletion Request',
    55: 'Session Deletion Response',
    56: 'Session Report Request',
    57: 'Session Report Response',
}

IE_TYPES = {
    1: 'Create PDR',
    2: 'PDI',
    3: 'Create FAR',
    4: 'Forwarding Parameters',
    5: 'Duplicating Parameters',
    6: 'Create URR',
    7: 'Create QER',
    8: 'Created PDR',
    9: 'Update PDR',
    10: 'Update FAR',
    11: 'Update Forwarding Parameters',
    12: 'Update BAR (PFCP Session Report Response)',
    13: 'Update URR',
    14: 'Update QER',
    15: 'Remove PDR',
    16: 'Remove FAR',
    17: 'Remove URR',
    18: 'Remove QER',
    19: 'Cause',
    20: 'Source Interface',
    21: 'F-TEID',
    22: 'Network Instance',
    23: 'SDF Filter',
    24: 'Application ID',
    25: 'Gate Status',
    26: 'MBR',
    27: 'GBR',
    28: 'QER Correlation ID',
    29: 'Precedence',
    30: 'Transport Level Marking',
    31: 'Volume Threshold',
    32: 'Time Threshold',
    33: 'Monitoring Time',
    34: 'Subsequent Volume Threshold',
    35: 'Subsequent Time Threshold',
    36: 'Inactivity Detection Time',
    37: 'Reporting Triggers',
    38: 'Redirect Information',
    39: 'Report Type',
    40: 'Offending IE',
    41: 'Forwarding Policy',
    42: 'Destination Interface',
    43: 'UP Function Features',
    44: 'Apply Action',
    45: 'Downlink Data Service Information',
    46: 'Downlink Data Notification Delay',
    47: 'DL Buffering Duration',
    48: 'DL Buffering Suggested Packet Count',
    49: 'PFCPSMReq-Flags',
    50: 'PFCPSRRsp-Flags',
    51: 'Load Control Information',
    52: 'Sequence Number',
    53: 'Metric',
    54: 'Overload Control Information',
    55: 'Timer',
    56: 'PDR ID',
    57: 'F-SEID',
    58: "Application ID's PFDs",
    59: 'PFD context',
    60: 'Node ID',
    61: 'PFD contents',
    62: 'Measurement Method',
    63: 'Usage Report Trigger',
    64: 'Measurement Period',
    65: 'FQ-CSID',
    66: 'Volume Measurement',
    67: 'Duration Measurement',
    68: 'Application Detection Information',
    69: 'Time of First Packet',
    70: 'Time of Last Packet',
    71: 'Quota Holding Time',
    72: 'Dropped DL Traffic Threshold',
    73: 'Volume Quota',
    74: 'Time Quota',
    75: 'Start Time',
    76: 'End Time',
    77: 'Query URR',
    78: 'Usage Report (Session Modification Response)',
    79: 'Usage Report (Session Deletion Response)',
    80: 'Usage Report (Session Report Request)',
    81: 'URR ID',
    82: 'Linked URR ID',
    83: 'Downlink Data Report',
    84: 'Outer Header Creation',
    85: 'Create BAR',
    86: 'Update BAR (Session Modification Request)',
    87: 'Remove BAR',
    88: 'BAR ID',
    89: 'CP Function Features',
    90: 'Usage Information',
    91: 'Application Instance ID',
    92: 'Flow Information',
    93: 'UE IP Address',
    94: 'Packet Rate',
    95: 'Outer Header Removal',
    96: 'Recovery Time Stamp',
    97: 'DL Flow Level Marking',
    98: 'Header Enrichment',
    99: 'Error Indication Report',
    100: 'Measurement Information',
    101: 'Node Report Type',
    102: 'User Plane Path Failure Report',
    103: 'Remote GTP-U Peer',
    104: 'UR-SEQN',
    105: 'Update Duplicating Parameters',
    106: 'Activate Predefined Rules',
    107: 'Deactivate Predefined Rules',
    108: 'FAR ID',
    109: 'QER ID',
    110: 'OCI Flags',
    111: 'PFCP Association Release Request',
    112: 'Graceful Release Period',
    113: 'PDN Type',
    114: 'Failed Rule ID',
    115: 'Time Quota Mechanism',
    116: 'User Plane IP Resource Information',
    117: 'User Plane Inactivity Timer',
    118: 'Aggregated URRs',
    119: 'Multiplier',
    120: 'Aggregated URR ID',
    121: 'Subsequent Volume Quota',
    122: 'Subsequent Time Quota',
    123: 'RQI',
    124: 'QFI',
    125: 'Query URR Reference',
    126: 'Additional Usage Reports Information',
    127: 'Create Traffic Endpoint',
    128: 'Created Traffic Endpoint',
    129: 'Update Traffic Endpoint',
    130: 'Remove Traffic Endpoint',
    131: 'Traffic Endpoint ID',
    132: 'Ethernet Packet Filter',
    133: 'MAC address',
    134: 'C-TAG',
    135: 'S-TAG',
    136: 'Ethertype',
    137: 'Proxying',
    138: 'Ethernet Filter ID',
    139: 'Ethernet Filter Properties',
    140: 'Suggested Buffering Packets Count',
    141: 'User ID',
    142: 'Ethernet PDU Session Information',
    143: 'Ethernet Traffic Information',
    144: 'MAC Addresses Detected',
    145: 'MAC Addresses Removed',
    146: 'Ethernet Inactivity Timer',
    147: 'Additional Monitoring Time',
    148: 'Event Quota',
    149: 'Event Threshold',
    150: 'Subsequent Event Quota',
    151: 'Subsequent Event Threshold',
    152: 'Trace Information',
    153: 'Framed-Route',
    154: 'Framed-Routing',
    155: 'Framed-IPv6-Route',
    156: 'Event Time Stamp',
    157: 'Averaging Window',
    158: 'Paging Policy Indicator',
    159: 'APN/DNN',
    160: '3GPP Interface Type',
}

GROUPED = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 58, 84, 85, 86, 87, 128, 129, 130}
MSG_SESSION_TYPES = {50, 51, 52, 53, 54, 55, 56, 57}


# ---------------------------------------------------------------- plumbing

def run(module, args, timeout=60):
    p = subprocess.run(["bash", module] + args, capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def fields(out):
    d = {}
    for ln in out.split("\n"):
        if "\t" in ln:
            k, v = ln.split("\t", 1)
            d.setdefault(k, v)
    return d


# ---------------------------------------------------------- the statements
# These builders are the clause restated; the check does not ask the module
# what a frame looks like.

def ref_ie(ie_type, value=b"", eid=None):
    """TS 29.244 §8.1.2."""
    t = ie_type if eid is None else (ie_type | 0x8000)
    if eid is None:
        length, body = len(value), value
    else:
        length, body = len(value) + 2, eid.to_bytes(2, "big") + value
    return t.to_bytes(2, "big") + length.to_bytes(2, "big") + body


def ref_msg(mtype, ies=b"", seid=1, seq=1, mp=0, prio=0, ver=1, spare_bits=0,
            s=None, length=None, tail_nibble=0):
    """TS 29.244 §7.2.2.1-§7.2.2.3."""
    if s is None:
        s = 1 if mtype in MSG_SESSION_TYPES else 0
    b0 = ((ver & 0x7) << 5) | ((spare_bits & 0x7) << 2) | ((mp & 0x1) << 1) | (s & 0x1)
    tail = b""
    if s == 1:
        tail += seid.to_bytes(8, "big")
    tail += (seq & 0xFFFFFF).to_bytes(3, "big")
    if mp == 1:
        tail += bytes([((prio & 0xF) << 4) | (tail_nibble & 0xF)])
    else:
        tail += bytes([tail_nibble & 0xF])
    payload = tail + ies
    declared = len(payload) if length is None else length
    return bytes([b0, mtype]) + declared.to_bytes(2, "big") + payload


CASES = []
MISMATCHES = []


def check(name, got, want):
    CASES.append(name)
    if got != want:
        MISMATCHES.append((name, want, got))
        return False
    return True


def check_rc(name, rc, want, out=""):
    CASES.append(name)
    if rc != want:
        MISMATCHES.append((name, "rc=%s" % want, "rc=%s %s" % (rc, out.strip()[:120])))
        return False
    return True


# ------------------------------------------------------------------- checks

def check_message_types(module, verbose=False):
    """Table 7.3-1: every one of the 256 type values."""
    for t in range(256):
        frame = ref_msg(t)
        rc, out = run(module, ["--decode-pfcp", frame.hex()])
        got = fields(out).get("message_type_name", "")
        if t in MSG_TYPES:
            want = MSG_TYPES[t]
        else:
            want = "unknown (%d)" % t
        check("msg-type-%d" % t, got, want)


def check_ie_names(module, verbose=False):
    """Table 8.1.2-1: every IE type, inside one message."""
    ies = b""
    order = sorted(IE_TYPES)
    for t in order:
        ies += ref_ie(t, b"" if t in GROUPED else b"\x00\x00")
    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ies).hex()])
    f = fields(out)
    for n, t in enumerate(order):
        check("ie-name-%d" % t, f.get("ie.%d.name" % n, ""), IE_TYPES[t])
        check("ie-len-%d" % t, f.get("ie.%d.length" % n, ""),
              "0" if t in GROUPED else "2")
    for t in (0, 161, 200, 254):
        rc, out = run(module, ["--decode-pfcp",
                               ref_msg(50, ies=ref_ie(t, b"\x00")).hex()])
        check("ie-unknown-%d" % t, fields(out).get("ie.0.name", ""),
              "unknown (%d)" % t)


def check_header(module, verbose=False):
    """§7.2.2.1-§7.2.2.3 and the two message classes."""
    ies = ref_ie(19, b"\x01")
    rc, out = run(module, ["--decode-pfcp", ref_msg(1, ies=ies).hex()])
    f = fields(out)
    check("hdr-node-version", f.get("version", ""), "1")
    check("hdr-node-type", f.get("message_type", ""), "1")
    check("hdr-node-length", f.get("length", ""), str(4 + len(ies)))
    check("hdr-node-actual", f.get("actual_octets", ""), str(8 + len(ies)))
    check("hdr-node-s", f.get("seid_present", ""), "no")
    check("hdr-node-seq", f.get("sequence", ""), "1")
    check("hdr-node-session", f.get("session_related", ""), "no")
    check("hdr-node-prio", f.get("message_priority", ""), "none (MP=0)")
    check("hdr-node-len-agrees", f.get("length_agrees", ""), "yes")

    rc, out = run(module, ["--decode-pfcp",
                           ref_msg(50, ies=ies, seid=0x0102030405060708,
                                   seq=0x0A0B0C).hex()])
    f = fields(out)
    check("hdr-sess-s", f.get("seid_present", ""), "yes")
    check("hdr-sess-seid", f.get("seid", ""), str(0x0102030405060708))
    check("hdr-sess-seid-hex", f.get("seid_hex", ""), "%016X" % 0x0102030405060708)
    check("hdr-sess-seq", f.get("sequence", ""), str(0x0A0B0C))
    check("hdr-sess-session", f.get("session_related", ""), "yes")
    check("hdr-sess-length", f.get("length", ""), str(12 + len(ies)))

    for prio in (0, 7, 15):
        rc, out = run(module, ["--decode-pfcp",
                               ref_msg(52, ies=ies, mp=1, prio=prio).hex()])
        f = fields(out)
        check("hdr-mp-%d-present" % prio, f.get("priority_present", ""), "yes")
        check("hdr-mp-%d-prio" % prio, f.get("message_priority", ""), str(prio))

    rc, out = run(module, ["--decode-pfcp",
                           ref_msg(50, ies=ies, length=12 + len(ies) + 4).hex()])
    check("hdr-len-mismatch", fields(out).get("length_agrees", "").split(" ")[0], "no")

    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ies, spare_bits=5).hex()])
    check_rc("hdr-spare-refused", rc, 1, out)
    check("hdr-spare-value", fields(out).get("spare_bits", ""), "5")

    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ies, ver=2).hex()])
    check_rc("hdr-version-refused", rc, 1, out)
    check("hdr-version-value", fields(out).get("version", ""), "2")

    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ies, s=0).hex()])
    check_rc("hdr-session-needs-s", rc, 1, out)

    rc, out = run(module, ["--decode-pfcp", ref_msg(1, ies=ies, mp=1, prio=3).hex()])
    check("hdr-node-mp-note", "note" in out, True)

    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ies, tail_nibble=9).hex()])
    check("hdr-tail-nibble-note", "note" in out, True)

    rc, out = run(module, ["--decode-pfcp", "21320004"])
    check_rc("hdr-short-refused", rc, 1, out)


def check_ies(module, verbose=False):
    """§8.1.2 and the grouped rule IEs of §7.5."""
    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ref_ie(19, b"\x01")).hex()])
    f = fields(out)
    check("ie-cause-type", f.get("ie.0.type", ""), "19")
    check("ie-cause-name", f.get("ie.0.name", ""), "Cause")
    check("ie-cause-length", f.get("ie.0.length", ""), "1")
    check("ie-cause-value", f.get("ie.0.value", ""), "01")
    check("ie-cause-vendor", f.get("ie.0.vendor", ""), "0")
    check("ie-count-one", f.get("ie_count", ""), "1")

    rc, out = run(module, ["--decode-pfcp",
                           ref_msg(50, ies=ref_ie(100, bytes.fromhex("A1B2"),
                                                  eid=10415)).hex()])
    f = fields(out)
    check("ie-vendor-type", f.get("ie.0.type", ""), "100")
    check("ie-vendor-flag", f.get("ie.0.vendor", ""), "1")
    check("ie-vendor-eid", f.get("ie.0.enterprise_id", ""), "10415")
    check("ie-vendor-length", f.get("ie.0.length", ""), "4")
    check("ie-vendor-value", f.get("ie.0.value", ""), "a1b2")

    inner = ref_ie(56, b"\x00\x07") + ref_ie(
        2, ref_ie(20, b"\x00") + ref_ie(21, bytes.fromhex("8A000000010A000001")))
    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ref_ie(1, inner)).hex()])
    f = fields(out)
    check("group-count", f.get("ie_count", ""), "1")
    check("group-name", f.get("ie.0.name", ""), "Create PDR")
    check("group-child-type", f.get("ie.0.0.type", ""), "56")
    check("group-child-name", f.get("ie.0.0.name", ""), "PDR ID")
    check("group-child-value", f.get("ie.0.0.value", ""), "0007")
    check("group-nest-type", f.get("ie.0.1.type", ""), "2")
    check("group-nest-name", f.get("ie.0.1.name", ""), "PDI")
    check("group-nest-child", f.get("ie.0.1.0.name", ""), "Source Interface")
    check("group-nest-fteid", f.get("ie.0.1.1.name", ""), "F-TEID")

    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=ref_ie(37, b"")).hex()])
    check("ie-empty-length", fields(out).get("ie.0.length", ""), "0")

    bad = ref_ie(19, b"\x01")[:-1]
    rc, out = run(module, ["--decode-pfcp", ref_msg(50, ies=bad).hex()])
    check_rc("ie-truncated-refused", rc, 1, out)

    rc, out = run(module, ["--decode-pfcp",
                           ref_msg(50, ies=ref_ie(19, b"\x01") + b"\x00\x13").hex()])
    check_rc("ie-leftover-refused", rc, 1, out)

    rc, out = run(module, ["--decode-pfcp",
                           ref_msg(50, ies=ref_ie(19, b"\x01") +
                                   ref_ie(60, b"\x01\x02\x03")).hex()])
    f = fields(out)
    check("ie-count", f.get("ie_count", ""), "2")
    check("ie-1-name", f.get("ie.1.name", ""), "Node ID")
    check("ie-1-length", f.get("ie.1.length", ""), "3")
    check("ie-1-value", f.get("ie.1.value", ""), "010203")


def check_pycrate(module, verbose=False):
    """pycrate's PFCP decoder on the same frames."""
    try:
        from pycrate_mobile.TS29244_PFCP import PFCPMsg
    except Exception as e:  # pragma: no cover
        print("NOTE\tpycrate is not importable here (%s); the cross-check is skipped" % e)
        return

    def pyc(frame):
        m = PFCPMsg()
        m.from_bytes(frame)
        hdr = m._content[0].get_val()
        ies = m._content[1].get_val() if len(m._content) > 1 else []
        return hdr, ies

    # PFCPHdr _GEN: 0 Version, 1 spare, 2 FO, 3 MP, 4 S, 5 Type, 6 Len,
    # 7 SEID, 8 SeqNum, 9 MPSel (int, or [MsgPriority, spare] when MP=1).
    cases = [
        ("node", ref_msg(1, ies=ref_ie(19, b"\x01"))),
        ("session", ref_msg(50, ies=ref_ie(19, b"\x01"), seid=7, seq=9)),
        ("priority", ref_msg(52, ies=ref_ie(19, b"\x01"), mp=1, prio=11)),
        ("vendor", ref_msg(50, ies=ref_ie(100, bytes.fromhex("A1B2"), eid=10415))),
        ("multi", ref_msg(50, ies=ref_ie(19, b"\x01") + ref_ie(60, b"\x05"))),
        ("empty", ref_msg(50)),
    ]
    for name, frame in cases:
        hdr, ies = pyc(frame)
        rc, out = run(module, ["--decode-pfcp", frame.hex()])
        f = fields(out)
        check("pycrate-%s-version" % name, f.get("version", ""), str(hdr[0]))
        check("pycrate-%s-type" % name, f.get("message_type", ""), str(hdr[5]))
        check("pycrate-%s-len" % name, f.get("length", ""), str(hdr[6]))
        check("pycrate-%s-seq" % name, f.get("sequence", ""), str(hdr[8]))
        if hdr[4] == 1:
            check("pycrate-%s-seid" % name, f.get("seid", ""), str(hdr[7]))
        else:
            check("pycrate-%s-s-zero" % name, f.get("seid_present", ""), "no")
        if hdr[3] == 1:
            prio = hdr[9][0] if isinstance(hdr[9], list) else 0
            check("pycrate-%s-prio" % name, f.get("message_priority", ""), str(prio))
        mod_ies = []
        n = 0
        while ("ie.%d.type" % n) in f:
            mod_ies.append((int(f["ie.%d.type" % n]), int(f["ie.%d.length" % n])))
            n += 1
        # pycrate keeps the V flag in the type it reports; the flag is
        # compared separately, the number without it.
        pyc_ies = [(int(i[0]) & 0x7FFF, int(i[1])) for i in ies]
        check("pycrate-%s-ies" % name, mod_ies, pyc_ies)
        for n, i in enumerate(ies):
            if int(i[0]) & 0x8000:
                check("pycrate-%s-ies-%d-vendor" % (name, n),
                      f.get("ie.%d.vendor" % n, ""), "1")


CHECKS = {
    "message_types": check_message_types,
    "ie_names": check_ie_names,
    "header": check_header,
    "ies": check_ies,
    "pycrate": check_pycrate,
}

# (name, anchor that must exist in the module, replacement, check it must break)
MUTANTS = [
    ("ie-56-named-packet-detection-rule-id",
     "\n56\tPDR ID\n", "\n56\tPacket Detection Rule ID\n", "ie_names"),
    ("ie-41-named-offending-ie",
     "\n41\tForwarding Policy\n", "\n41\tOffending IE\n", "ie_names"),
    ("length-counts-the-header",
     "if (( mlen != total - 4 )); then", "if (( mlen != total )); then", "header"),
    ("session-related-flag-ignored",
     '    if ncore_pfcp_session_type "$mtype" && (( s == 0 )); then',
     "    if false; then", "header"),
    ("vendor-id-left-in-the-value",
     '"${val:4}"', '"${val}"', "ies"),
]


def negctl(module, verbose=False):
    src = open(module).read()
    caught = 0
    for name, anchor, new, which in MUTANTS:
        if anchor not in src:
            print("NEGCTL\t%s\tMISSED (anchor not found)" % name)
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(src.replace(anchor, new, 1))
            path = fh.name
        os.chmod(path, 0o755)
        before = len(MISMATCHES)
        CHECKS[which](path, verbose)
        n = len(MISMATCHES) - before
        os.unlink(path)
        if n:
            caught += 1
            print("NEGCTL\t%s\tCAUGHT (%d mismatches)" % (name, n))
        else:
            print("NEGCTL\t%s\tMISSED" % name)
    return 0 if caught == len(MUTANTS) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=MODULE)
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    if args.negctl:
        return negctl(args.module, args.verbose)
    names = [n for n in CHECKS if not args.only or n in args.only.split(",")]
    for name in names:
        CHECKS[name](args.module, args.verbose)
    print("CASES\t%d" % len(CASES))
    print("MISMATCHES\t%d" % len(MISMATCHES))
    for name, want, got in MISMATCHES[:40]:
        print("MISMATCH\t%s\twant=%r\tgot=%r" % (name, want, got))
    if MISMATCHES:
        print("RESULT\tFAIL(%d)" % len(MISMATCHES))
        return 1
    print("RESULT\tPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
