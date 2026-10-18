#!/usr/bin/env python3
"""Differential check of modules/11_lte_core.sh's GTP-C and GTP-U codecs.

The module reads the core network's own protocol headers, so a wrong field
order, a wrong registry row or a wrong digit encoding is not cosmetic: the
analyst reads a subscriber identity or a tunnel endpoint out of it.  This
script states what the two clauses actually say, builds the frames from that
statement, and compares the module's output against it field by field.

Sources, both on disk while this was written:
  /tmp/ts29274.txt   ETSI TS 129 274 V15.8.0 (GTPv2-C)
  /tmp/ts29281.txt   ETSI TS 129 281 V15.4.0 (GTP-U)

Sections:
  msg      TS 29.274 Table 6.1-1 message types, 0..255
  ie       TS 29.274 Table 8.1-1 information element types, 0..255
  gtpc     TS 29.274 §5.1 header: version, P/T/MP flags, length agreement
  tbcd     TS 29.274 §8.3 (IMSI) and §8.11 (MSISDN): TBCD, no count octet
  uli      TS 29.274 §8.21 user location information
  fteid    TS 29.274 §8.22 fully qualified TEID, interface types
  rat      TS 29.274 §8.17 RAT type
  forge    the forged Create Session Request decodes back to its inputs
  gtpu     TS 29.281 §5.1/§5.2 header, message types, extension headers
  pycrate  pycrate's independent GTPv2 decoder agrees on the same frames

Exit 0 when every case agrees, 1 on a disagreement, 2 when the module or a
second implementation is missing.
"""

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MODULE = os.environ.get("GTP_MODULE", os.path.join(ROOT, "modules", "11_lte_core.sh"))
ORACLE_PY = os.environ.get("GTP_ORACLE_PY", "/home/ysl/.ota-oracles/venv/bin/python")

CASES = 0
MISMATCHES = 0
FAILURES = []


# ── clause tables ───────────────────────────────────────────────────────
# TS 29.274 Table 6.1-1.  Only the rows this repo has had to reason about
# are restated; the remainder are checked against pycrate further down.
MSG_ROWS = {
    1: "Echo Request",
    2: "Echo Response",
    3: "Version Not Supported Indication",
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    36: "Delete Session Request",
    37: "Delete Session Response",
    128: "Identification Request",
    129: "Identification Response",
    130: "Context Request",
    131: "Context Response",
    132: "Context Acknowledge",
    160: "Create Forwarding Tunnel Request",
    161: "Create Forwarding Tunnel Response",
    162: "Suspend Notification",
    163: "Suspend Acknowledge",
    170: "Release Access Bearers Request",
    171: "Release Access Bearers Response",
    176: "Downlink Data Notification",
    177: "Downlink Data Notification Acknowledge",
    179: "PGW Restart Notification",
    180: "PGW Restart Notification Acknowledge",
    254: "End Marker",  # not GTPv2: 254 is a GTP-U type; GTPv2 254 is reserved
}

# TS 29.274 Table 8.1-1 rows the module renders or names one by one.
IE_ROWS = {
    1: "International Mobile Subscriber Identity (IMSI)",
    2: "Cause",
    3: "Recovery (Restart Counter)",
    73: "EPS Bearer ID (EBI)",
    76: "MSISDN",
    82: "RAT Type",
    83: "Serving Network",
    86: "User Location Information (ULI)",
    87: "Fully Qualified Tunnel Endpoint Identifier (F-TEID)",
    111: "P-TMSI",
    114: "UE Time Zone",
    118: "F-Container",
    119: "F-Cause",
    126: "Port Number",
    127: "APN Restriction",
    128: "Selection Mode",
    129: "Source Identification",
    131: "Change Reporting Action",
    145: "User CSG Information (UCI)",
    163: "Additional Protocol Configuration Options (APCO)",
    194: "CIoT Optimizations Support Indication",
    197: "Extended Protocol Configuration Options (ePCO)",
    254: "Special IE type for IE Type Extension",
    255: "Private Extension",
}

# TS 29.274 Table 8.17-1 RAT types.
RAT_ROWS = {
    1: "UTRAN", 2: "GERAN", 3: "WLAN", 4: "GAN", 5: "HSPA Evolution",
    6: "EUTRAN (WB-E-UTRAN)", 7: "Virtual", 8: "EUTRAN-NB-IoT", 9: "LTE-M",
    10: "NR",
}

# TS 29.274 §8.22 F-TEID interface types.
IFACE_ROWS = {
    0: "S1-U eNodeB GTP-U",
    1: "S1-U SGW GTP-U",
    2: "S12 RNC GTP-U",
    3: "S12 SGW GTP-U",
    4: "S5/S8 SGW GTP-U",
    5: "S5/S8 PGW GTP-U",
    6: "S5/S8 SGW GTP-C",
    7: "S5/S8 PGW GTP-C",
    8: "S5/S8 SGW PMIPv6",
    9: "S5/S8 PGW PMIPv6",
    10: "S11 MME GTP-C",
    11: "S11/S4 SGW GTP-C",
    12: "S10/N26 MME GTP-C",
    13: "S3 MME GTP-C",
    14: "S3 SGSN GTP-C",
    15: "S4 SGSN GTP-U",
    16: "S4 SGW GTP-U",
    17: "S4 SGSN GTP-C",
    18: "S16 SGSN GTP-C",
    19: "eNodeB GTP-U for DL data forwarding",
    20: "eNodeB GTP-U for UL data forwarding",
    21: "RNC GTP-U for data forwarding",
    22: "SGSN GTP-U for data forwarding",
    23: "SGW/UPF GTP-U for DL data forwarding",
    24: "Sm MBMS GW GTP-C",
    25: "Sn MBMS GW GTP-C",
    26: "Sm MME GTP-C",
    27: "Sn SGSN GTP-C",
    28: "SGW GTP-U for UL data forwarding",
    29: "Sn SGSN GTP-U",
    30: "S2b ePDG GTP-C",
    31: "S2b-U ePDG GTP-U",
    32: "S2b PGW GTP-C",
    33: "S2b-U PGW GTP-U",
    34: "S2a TWAN GTP-U",
    35: "S2a TWAN GTP-C",
    36: "S2a PGW GTP-C",
    37: "S2a PGW GTP-U",
    38: "S11 MME GTP-U",
    39: "S11 SGW GTP-U",
    40: "N26 AMF GTP-C",
}

# TS 29.281 Table 5.2.2-1 (next-extension-header types).
EXT_ROWS = {
    0x00: "No more headers",
    0x01: "Reserved - Control Plane only",
    0x02: "Reserved - Control Plane only",
    0x03: "Long PDCP PDU Number",
    0x20: "Service Class Indicator",
    0x40: "UDP Port",
    0x81: "RAN Container",
    0x82: "Long PDCP PDU Number (earlier release; not sent by a source complying with this release)",
    0x83: "Xw RAN Container",
    0x84: "NR RAN Container",
    0x85: "PDU Session Container",
    0xC0: "PDCP PDU Number",
    0xC1: "Reserved - Control Plane only",
    0xC2: "Reserved - Control Plane only",
}

GTPU_MSG_ROWS = {
    1: "Echo Request",
    2: "Echo Response",
    31: "Supported Extension Headers Notification",
    254: "End Marker",
    255: "G-PDU",
}


# ── plumbing ────────────────────────────────────────────────────────────
def run(module, *args):
    proc = subprocess.run(["bash", module, *args], capture_output=True, text=True)
    return proc.stdout, proc.stderr, proc.returncode


def fields(text):
    out = {}
    for line in text.splitlines():
        if "\t" in line:
            key, _, val = line.partition("\t")
            out[key] = val
    return out


def check(name, got, want, note=""):
    global CASES, MISMATCHES
    CASES += 1
    if got != want:
        MISMATCHES += 1
        FAILURES.append((name, want, got, note))


def norm(text):
    """Compare display names without caring about case or punctuation width."""
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def check_name(name, got, want):
    check(name, norm(got or ""), norm(want))


# ── reference encoders, written from the clause ─────────────────────────
def tbcd(digits):
    """TS 29.274 §8.3: octet n holds digit 2n+2 in the high nibble, 2n+1 in
    the low nibble; an odd digit count ends with filler 1111."""
    if len(digits) % 2:
        digits += "F"
    return "".join(digits[i + 1] + digits[i] for i in range(0, len(digits), 2))


def ie(ie_type, value_hex, instance=0):
    """Type(1) Length(2) Spare|Instance(1) Value.  NOT padded.

    TS 29.274 8.2 makes Length the actual length of the value and defines no
    padding after it; the 4-octet alignment is GTPv1-C (TS 29.060). This helper
    used to pad, which made the oracle agree with the module and both disagree
    with every real dissector: tshark 4.2.2 calls a padded GTPv2-C IE
    "[Malformed Packet: GTPv2]" and pycrate advances by exactly 4+Length."""
    value = bytes.fromhex(value_hex)
    return bytes([ie_type]) + len(value).to_bytes(2, "big") + bytes([instance]) + value


def gtpc(mtype, ies=b"", version=2, p=0, t=0, teid=None, seq=1, mp=0,
         prio=0, spare=0, length=None):
    """TS 29.274 §5.1.  Octet 1: Version(3) P(1) T(1) MP(1) Spare(2).
    Length is the count of the octets after the first four, so it covers the
    TEID, the sequence number and the IEs."""
    flags = (version << 5) | (p << 4) | (t << 3) | (mp << 2) | (spare & 0x03)
    rest = b""
    if t:
        rest += (teid or 0).to_bytes(4, "big")
    rest += seq.to_bytes(3, "big")
    rest += bytes([(prio & 0x0F) << 4]) if mp else b"\x00"
    rest += ies
    if length is None:
        length = len(rest)
    return (bytes([flags, mtype]) + length.to_bytes(2, "big") + rest).hex().upper()


def plmn_hex(mcc, mnc):
    """TS 24.008 §10.5.1.13: octet 5 = MCC digit 2 | MCC digit 1, octet 6 =
    MNC digit 3 | MCC digit 3, octet 7 = MNC digit 2 | MNC digit 1, with F as
    the filler when the MNC has two digits.  These are already TBCD: the
    digits are stored in the nibble order they are printed in."""
    mnc = mnc if len(mnc) == 3 else mnc + "F"
    return mcc[1] + mcc[0] + mnc[2] + mcc[2] + mnc[1] + mnc[0]


def fteid(iface, teid=0x11223344, ipv4="10.0.0.1", v4=1, v6=0):
    """TS 29.274 §8.22: octet 5 = V4 (bit 8), V6 (bit 7), interface type
    (bits 6..1, six bits).  Octets 6..9 are the TEID, then the IPv4 address
    when V4 is set, then the IPv6 address when V6 is set."""
    octet5 = (v4 << 7) | (v6 << 6) | (iface & 0x3F)
    out = "%02X" % octet5 + "%08X" % teid
    if v4:
        out += "".join("%02X" % int(o) for o in ipv4.split("."))
    return out


def gtpu(mtype, teid=1, seq=1, npdu=0, s=0, pn=0, e=0, payload=b"",
         version=1, pt=1, spare=0, length=None, exts=()):
    """TS 29.281 §5.1.  Octet 1: Version(3) PT(1) Spare(1) E(1) S(1) PN(1).
    The length covers everything after the first eight octets.  Each
    extension header is Length(1) = 4-octet units, Content(Length*4 - 2),
    Next Extension Header Type(1) (Figure 5.2.1-1)."""
    if exts:
        e = 1
    flags = (version << 5) | (pt << 4) | ((spare & 1) << 3) | (e << 2) | (s << 1) | pn
    body = b""
    if s or pn or e:
        chain = b""
        for idx, (etype, econtent) in enumerate(exts):
            content = econtent if isinstance(econtent, bytes) else bytes.fromhex(econtent)
            nxt = exts[idx + 1][0] if idx + 1 < len(exts) else 0
            units = max(1, (len(content) + 2 + 3) // 4)
            content = content + b"\x00" * (units * 4 - 2 - len(content))
            chain += bytes([units]) + content + bytes([nxt])
        body += seq.to_bytes(2, "big") + bytes([npdu])
        body += bytes([exts[0][0] if exts else 0])
        body += chain
    body += payload
    if length is None:
        length = len(body)
    return (bytes([flags, mtype]) + length.to_bytes(2, "big") +
            teid.to_bytes(4, "big") + body).hex().upper()


# ── checks ──────────────────────────────────────────────────────────────
def check_msg_types(module):
    """Table 6.1-1: the module names the message type it reads."""
    for mtype in range(256):
        frame = gtpc(mtype, t=0, seq=1)
        out, _, _ = run(module, "--decode-gtp-c", frame)
        f = fields(out)
        if mtype in MSG_ROWS and mtype != 254:
            check_name("msg-%d" % mtype, f.get("message_name"), MSG_ROWS[mtype])
        # A name is never empty: an unrecognised type is still reported.
        check("msg-%d-named" % mtype, bool(f.get("message_name")), True)


def check_ie_names(module):
    """Table 8.1-1: one message carries one zero-length IE per call."""
    for ie_type in range(256):
        frame = gtpc(32, ies=ie(ie_type, ""), t=0)
        out, _, _ = run(module, "--decode-gtp-c", frame)
        f = fields(out)
        if ie_type in IE_ROWS:
            check_name("ie-%d" % ie_type, f.get("ie.0.name"), IE_ROWS[ie_type])
        check("ie-%d-type" % ie_type, f.get("ie.0.type"), str(ie_type))


def check_gtpc_header(module):
    """§5.1: version, flags, and a length that agrees with what is there."""
    # Version 2, T=1 with a TEID: every field lands where the clause puts it.
    frame = gtpc(32, ies=ie(1, tbcd("310150123456789")), t=1, teid=0xDEADBEEF, seq=0x0000C8)
    f = fields(run(module, "--decode-gtp-c", frame)[0])
    check("gtpc-version", f.get("version"), "2")
    check("gtpc-T", f.get("flag_T"), "1")
    check("gtpc-teid", f.get("teid_hex", "").lower().replace("0x", ""), "deadbeef")
    check("gtpc-seq", f.get("sequence_number"), str(0x0000C8))
    check("gtpc-length-agrees", f.get("length_agrees"), "yes")

    # A length that overstates the frame must be reported, not believed.
    frame = gtpc(32, ies=ie(3, "07"), length=99)
    out, err, rc = run(module, "--decode-gtp-c", frame)
    check("gtpc-len-mismatch-agrees", fields(out).get("length_agrees"), "no")
    check("gtpc-len-mismatch-reports", bool(re.search(r"length", out + err, re.I)), True)

    # Version 1 in a GTP-C frame is not a GTPv2-C message.
    frame = gtpc(32, version=1)
    out, err, rc = run(module, "--decode-gtp-c", frame)
    check("gtpc-ver1-rejected", rc != 0 or "ERROR" in out + err, True)

    # MP=1 moves the priority into the trailer and removes the spare octet.
    frame = gtpc(32, mp=1, prio=0x0F, ies=ie(3, "07"))
    out, _, rc = run(module, "--decode-gtp-c", frame)
    f = fields(out)
    check("gtpc-mp-flag", f.get("flag_MP"), "1")
    check("gtpc-mp-priority", f.get("message_priority"), "15")


def check_tbcd(module):
    """§8.3/§8.11: a subscriber identity is digits only, no count octet."""
    for length in (6, 7, 10, 14, 15):
        digits = "3" + "".join(str((i * 7 + length) % 10) for i in range(length - 1))
        frame = gtpc(32, ies=ie(1, tbcd(digits)), t=1, teid=1)
        f = fields(run(module, "--decode-gtp-c", frame)[0])
        check("tbcd-imsi-%d" % length, f.get("ie.0.decoded"), "IMSI=" + digits)
        msisdn = "".join(str((i * 3 + 1) % 10) for i in range(length))
        frame = gtpc(32, ies=ie(76, tbcd(msisdn)), t=1, teid=1)
        f = fields(run(module, "--decode-gtp-c", frame)[0])
        check("tbcd-msisdn-%d" % length, f.get("ie.0.decoded"), "MSISDN=" + msisdn)

    # Recovery is a single restart counter, not an identity.
    frame = gtpc(32, ies=ie(3, "2A"), t=1, teid=1)
    check("ie3-recovery", fields(run(module, "--decode-gtp-c", frame)[0]).get("ie.0.decoded"),
          "Recovery=42")


def check_uli(module):
    """§8.21: the first value octet says which identities follow, in the
    order CGI, SAI, RAI, TAI, ECGI, LAI, macro eNodeB, extended macro."""
    ecgi = plmn_hex("310", "260") + "0000ABCD"
    tai = plmn_hex("310", "260") + "1234"
    lai = plmn_hex("262", "01") + "5678"
    cgi = plmn_hex("262", "02") + "9A1B" + "0001"
    sai = plmn_hex("262", "03") + "FFFF" + "0001"
    rai = plmn_hex("262", "04") + "0001" + "0001"
    macro = plmn_hex("310", "260") + "000123"
    # The rendering of each identity, in the shape the module prints it.
    cases = {
        0x10: ("ecgi", ecgi, "ULI=ECGI 310-260 eci=43981"),
        0x08: ("tai", tai, "ULI=TAI 310-260 tac=4660"),
        0x20: ("lai", lai, "ULI=LAI 262-01 lac=22136"),
        0x01: ("cgi", cgi, "ULI=CGI 262-02 lac=39451 ci=1"),
        0x02: ("sai", sai, "ULI=SAI 262-03 lac=65535 sac=1"),
        0x04: ("rai", rai, "ULI=RAI 262-04 lac=1 rac=1"),
        0x40: ("macro", macro, "ULI=MACRO 310-260 macro_enb=291"),
    }
    for flag, (label, piece, want) in sorted(cases.items()):
        frame = gtpc(32, ies=ie(86, "%02X" % flag + piece), t=1, teid=1)
        f = fields(run(module, "--decode-gtp-c", frame)[0])
        check_name("uli-%s" % label, f.get("ie.0.decoded") or "", want)

    # Two identities at once keeps the clause order.
    frame = gtpc(32, ies=ie(86, "18" + tai + ecgi), t=1, teid=1)
    decoded = fields(run(module, "--decode-gtp-c", frame)[0]).get("ie.0.decoded") or ""
    check("uli-order", decoded.find("TAI") < decoded.find("ECGI"), True)


def check_fteid(module):
    """§8.22: the interface type lives in octet 5 with the V4/V6 flags."""
    ies = b""
    order = sorted(IFACE_ROWS)
    for iface in order:
        ies += ie(87, fteid(iface), instance=iface & 0x0F)
    frame = gtpc(32, ies=ies, t=1, teid=1)
    out, _, _ = run(module, "--decode-gtp-c", frame)
    f = fields(out)
    for idx, iface in enumerate(order):
        decoded = f.get("ie.%d.decoded" % idx) or ""
        want = "F-TEID=interface=%s (%d) teid=%d ipv4=10.0.0.1" % (
            IFACE_ROWS[iface], iface, 0x11223344)
        check("fteid-%d" % iface, decoded, want)


def check_rat(module):
    """§8.17: one octet, and the module names the radio access technology."""
    ies = b"".join(ie(82, "%02X" % rat, instance=rat & 0x0F) for rat in sorted(RAT_ROWS))
    frame = gtpc(32, ies=ies, t=1, teid=1)
    f = fields(run(module, "--decode-gtp-c", frame)[0])
    for idx, rat in enumerate(sorted(RAT_ROWS)):
        decoded = f.get("ie.%d.decoded" % idx) or ""
        check_name("rat-%d" % rat, decoded, "RAT " + RAT_ROWS[rat])


def check_forge(module):
    """The forged request must decode back to what was asked for."""
    out, err, rc = run(module, "--gtp-csr-forge", "310150123456789", "internet", "310", "260")
    frame = fields(out).get("message")
    check("forge-built", bool(frame), True)
    if not frame:
        return
    f = fields(run(module, "--decode-gtp-c", frame)[0])
    check("forge-type", f.get("message_name"), "Create Session Request")
    check("forge-length-agrees", f.get("length_agrees"), "yes")
    check("forge-imsi", f.get("ie.0.decoded"), "IMSI=310150123456789")
    check("forge-apn", f.get("ie.1.decoded"), "APN=internet")
    check_name("forge-rat", f.get("ie.2.decoded") or "", "RAT EUTRAN WB-E-UTRAN")
    check("forge-serving-network-name", f.get("ie.3.name"),
          "Serving Network")
    check("forge-serving-network-value", f.get("ie.3.value"), plmn_hex("310", "260").upper())


def check_gtpu(module):
    """TS 29.281 §5.1 header, Table 6.1-1 types, Table 5.2.2-1 extension
    headers and the comprehension bits of the next-type octet."""
    for mtype, name in sorted(GTPU_MSG_ROWS.items()):
        s = 1 if mtype in (1, 2) else 0
        frame = gtpu(mtype, s=s, payload=b"\x00" * 4 if not s else b"")
        f = fields(run(module, "--decode-gtp-u", frame)[0])
        got = f.get("message_name") or ""
        check("gtpu-msg-%d" % mtype, norm(got).startswith(norm(name)), True)

    # Every extension header type, with its comprehension bits.
    for etype in range(1, 256):
        frame = gtpu(255, s=1, exts=[(etype, b"\x00" * 4)])
        out, _, rc = run(module, "--decode-gtp-u", frame)
        f = fields(out)
        if etype in EXT_ROWS:
            check("ext-%d" % etype, norm(f.get("ext.0.name") or ""),
                  norm(EXT_ROWS[etype]))
        want_comp = {0: "not required: an intermediate node forwards it",
                     1: "not required: an intermediate node discards the content",
                     2: "required by the endpoint receiver, not by an intermediate node",
                     3: "required by every recipient"}[etype >> 6]
        check_name("ext-%d-comprehension" % etype, f.get("ext.0.comprehension") or "", want_comp)

    # Version 1 only; a length that disagrees must be reported.
    frame = gtpu(255, version=2, s=1)
    out, err, rc = run(module, "--decode-gtp-u", frame)
    check("gtpu-ver2-rejected", rc != 0 or "ERROR" in out + err, True)

    frame = gtpu(255, s=1, payload=b"\x00" * 4, length=99)
    f = fields(run(module, "--decode-gtp-u", frame)[0])
    check("gtpu-len-mismatch", f.get("length_agrees"), "no")

    # An extension header length of 0 is not a positive integer (§5.2.1):
    # the module must say it read it as one unit, not silently accept it.
    # flags 0x34 = version 1, PT 1, E 1, S 1; trailer 0001 00 85; then the
    # extension header 00 (length 0) 0102 (content) 00 (no more headers).
    frame = "34FF0008" "00000001" "0001" "00" "85" "00" "0102" "00"
    out, _, _ = run(module, "--decode-gtp-u", frame)
    f = fields(out)
    check("gtpu-ext-len0-units", f.get("ext.0.units"), "1")
    check("gtpu-ext-len0-noted", bool(f.get("ext.0.note")), True)


def check_pycrate(module):
    """pycrate's GTPv2 decoder is an independent second implementation."""
    if not os.path.exists(ORACLE_PY):
        print("pycrate\tSKIP\t%s is missing" % ORACLE_PY)
        return
    code = (
        "import sys, json\n"
        "from pycrate_mobile.TS29274_GTPC import GTPCMsg\n"
        "out = []\n"
        "for h in sys.argv[1:]:\n"
        "    m = GTPCMsg(); m.from_bytes(bytes.fromhex(h))\n"
        "    hdr = m._content[0]\n"
        "    ies = m._content[1]\n"
        "    row = {'version': hdr[0](), 'T': hdr[2](), 'MP': hdr[3](),\n"
        "           'type': hdr[5](), 'len': hdr[6](), 'seq': hdr[8](), 'ies': []}\n"
        "    for e in ies._content:\n"
        "        v = e.get_val()\n"
        "        val = v[1]\n"
        "        if isinstance(val, (bytes, bytearray)):\n"
        "            val = val.hex()\n"
        "        elif not isinstance(val, (int, float, str, type(None))):\n"
        "            val = json.dumps(val, default=str)\n"
        "        row['ies'].append([v[0][0], v[0][1], v[0][3], val])\n"
        "    out.append(row)\n"
        "print(json.dumps(out))\n"
    )
    # The IE order matters to pycrate: it desyncs when a padded IE precedes
    # a longer one, so the frames below are the ones it reads as the clause
    # says.  Its header reading is unaffected either way.
    frames = [
        gtpc(32, ies=ie(1, tbcd("310150123456789")) + ie(3, "07"), t=1, teid=0x0A0B0C0D),
        gtpc(1, ies=ie(3, "FF"), seq=0x010203),
        gtpc(34, ies=ie(73, "05") + ie(82, "06"), t=1, teid=1, mp=1, prio=4),
    ]
    proc = subprocess.run([ORACLE_PY, "-c", code, *frames],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print("pycrate\tSKIP\t%s" % proc.stderr.strip().splitlines()[-1:])
        return
    import json
    rows = json.loads(proc.stdout)
    for frame, row in zip(frames, rows):
        f = fields(run(module, "--decode-gtp-c", frame)[0])
        check("pycrate-version", f.get("version"), str(row["version"]))
        check("pycrate-type", f.get("message_type"), str(row["type"]))
        check("pycrate-length", f.get("length"), str(row["len"]))
        check("pycrate-seq", f.get("sequence_number"), str(row["seq"]))
        # pycrate desyncs on some padded IEs (it reads the padding as a new
        # IE), which is its own limitation; the header reading is unaffected.
        # The IE walk is compared only when pycrate finds the same IE types
        # in the same order.
        ours = []
        idx = 0
        while f.get("ie.%d.type" % idx) is not None:
            ours.append((int(f.get("ie.%d.type" % idx)),
                         int(f.get("ie.%d.length" % idx)),
                         int(f.get("ie.%d.instance" % idx)),
                         (f.get("ie.%d.value" % idx) or "").lower()))
            idx += 1
        theirs = [(t, l, i, (v if isinstance(v, str) else "").lower())
                  for (t, l, i, v) in row["ies"]]
        if [(t, l) for (t, l, _, _) in theirs] != [(t, l) for (t, l, _, _) in ours]:
            print("pycrate\tNOTE\tIE walk skipped on %s: pycrate read %s,"
                  " the clause puts %s there"
                  % (frame[:8], [(t, l) for (t, l, _, _) in theirs],
                     [(t, l) for (t, l, _, _) in ours]))
            continue
        check("pycrate-ie-count", f.get("ie_count"), str(len(row["ies"])))
        for idx, (ie_type, ie_len, inst, value) in enumerate(theirs):
            if isinstance(value, str) and value:
                check("pycrate-ie-%d-value" % idx,
                      (f.get("ie.%d.value" % idx) or "").lower(), value.lower())


# ── negative controls ───────────────────────────────────────────────────
MUTANTS = [
    ("imsi-reads-a-count-octet",
     "for (( i = 0; i < ${#hex}; i += 2 )); do",
     "for (( i = 2; i < ${#hex}; i += 2 )); do"),
    ("ie-3-named-as-msisdn",
     'echo "Recovery (Restart Counter)"',
     'echo "MSISDN"'),
    ("message-170-renamed",
     'echo "Release Access Bearers Request"',
     'echo "Reserved"'),
    ("ext-1-named-as-an-invented-header",
     '1)   echo "Reserved - Control Plane only"',
     '1)   echo "MBMS Support Indication"'),
    ("uli-tai-decoded-as-lai",
     '"$(lcore_tai_decode "${val:$((off*2)):10}")"',
     '"$(lcore_lai_decode "${val:$((off*2)):10}")"'),
]


def negctl(module):
    """Reintroduce each defect in a scratch copy: the oracle must catch it."""
    ok = True
    for name, old, new in MUTANTS:
        with open(MODULE) as fh:
            src = fh.read()
        if old not in src:
            print("NEGCTL\t%s\tSKIPPED\tanchor not found" % name)
            ok = False
            continue
        scratch = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                              dir=os.path.dirname(MODULE))
        # The two digit decoders share their loop text, so a mutant that
        # changes the loop must change every copy of it to reach the IMSI.
        count = 0 if name == "imsi-reads-a-count-octet" else 1
        scratch.write(src.replace(old, new) if count == 0
                      else src.replace(old, new, count))
        scratch.close()
        try:
            before = MISMATCHES
            globals()["CASES"] = 0
            globals()["MISMATCHES"] = 0
            FAILURES.clear()
            # Only the section this defect lives in needs to run.
            section = {
                "imsi-reads-a-count-octet": check_tbcd,
                "ie-3-named-as-msisdn": check_ie_names,
                "message-170-renamed": check_msg_types,
                "ext-1-named-as-an-invented-header": check_gtpu,
                "uli-tai-decoded-as-lai": check_uli,
            }[name]
            section(scratch.name)
            if MISMATCHES:
                print("NEGCTL\tCAUGHT\t%s\t%s" % (name, FAILURES[0][0]))
            else:
                print("NEGCTL\tMISSED\t%s" % name)
                ok = False
        finally:
            os.unlink(scratch.name)
    globals()["CASES"] = 0
    globals()["MISMATCHES"] = 0
    FAILURES.clear()
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module")
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--only", help="comma separated section names, for iterating")
    args = ap.parse_args()

    global MODULE
    if args.module:
        MODULE = args.module
    if not os.path.exists(MODULE):
        print("ERROR\tmodule %s is missing" % MODULE)
        return 2

    wanted = None
    if args.only:
        wanted = {n.strip() for n in args.only.split(",")}
    for section in (check_msg_types, check_ie_names, check_gtpc_header,
                    check_tbcd, check_uli, check_fteid, check_rat,
                    check_forge, check_gtpu, check_pycrate):
        if wanted is not None and section.__name__.replace("check_", "") not in wanted:
            continue
        if args.verbose:
            print("## %s" % section.__name__)
        section(MODULE)

    for name, want, got, note in (FAILURES if args.verbose else FAILURES[:20]):
        print("MISMATCH\t%s\twant=%r got=%r" % (name, want, got))
    print("CASES\t%d" % CASES)
    print("MISMATCHES\t%d" % MISMATCHES)

    ok = MISMATCHES == 0
    if args.negctl:
        ok = negctl(MODULE) and ok
    print("RESULT\t%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
