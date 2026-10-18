#!/usr/bin/env python3
"""XnAP codec check against TS 38.423 and pycrate.

tools/xnap_asn1.py writes XnSetupRequest octets -- the first message two
NG-RAN nodes exchange. A wrong IE number there hands the peer's identity or
its tracking area to the wrong field, and a wrong bit width produces a
message that dissects without complaint and says something else. So the tool
is checked against the clause statement of the layout and against a second
implementation, never against itself.

What the clause says (ETSI TS 138 423 V16.2.0, with X.691 for the encoding),
and what this check pins:

  §9.1   XnAP-PDU is a CHOICE of three root alternatives, extensible: the
         discriminator is one octet, 0x00 for initiatingMessage.
  §9.1   InitiatingMessage is SEQUENCE { procedureCode, criticality,
         value }: no preamble, so the procedure code is the second octet,
         the criticality the third, then the body as an open type.
  §9.3   id-xnSetup is 17. The table's first row is not XnSetup -- reading
         the procedure number off the order of the list gives 1, which is
         id-sNStatusTransfer, and the message then decodes as a transfer.
  §9.3   Criticality is extensible ENUMERATED: reject 0x00, ignore 0x40,
         notify 0x80.
  §9.3   ProtocolIE-Container is SEQUENCE (SIZE(0..65535)) OF
         ProtocolIE-Field and the SEQUENCE is extensible: one preamble bit,
         an alignment, then a sixteen-bit count.
  §9.3   The IE ids: AMF-Region-Information 4, GlobalNG-RANNode-ID 14,
         TAISupport-List 75. XnSetupRequest carries all three as mandatory
         IEs, so a message missing one is not an XnSetupRequest.
  X.691 §14    GlobalNG-RANNode-ID chooses gNB with two bits then aligns,
         because the next field is a three-octet PLMN; gNB-ID then carries a
         FOUR-bit length of length, padded to an octet, before the 22-bit
         identifier -- so 0xA1C01 writes `00 28 70 04` in the 22-bit case.
  X.691 §13.2  AMF-Region-Information is SEQUENCE (SIZE(1..max)) OF
         { plmn-ID, amf-region-id }: the count is one octet, value minus one.
  X.691 §13.2  TAISupport-List's count is one octet, and the TAI item's
         preamble is two bits (extensions, iE-Extensions) aligned to an
         octet because a TAC is an octet string of three.
  X.691 §13.2  broadcastPLMNs is SEQUENCE (SIZE(1..12)): a FOUR-bit count.
         An eight-bit count is accepted by nothing and shifts every following
         field by four bits, which still parses as a PLMN and a slice list.
  X.691 §13.2  tAISliceSupport-List's count is SIXTEEN bits, and its
         S-NSSAI items are eleven bits each, NOT padded between items: three
         bits of preamble (extension, sd present, iE-Extensions present) then
         sst as eight unaligned bits. `sst 0x01` therefore ends the list as
         `00 20`, and the last octet of a one-item list is not the sst.

pycrate 0.8.1's pycrate_asn1dir.XnAP is the second implementation: it is
given the same values through its own structure and must produce the same
octets, and it must read the tool's octets back to those values.

Three defects put back into the tool must each make this check fail:
  * the slice list count narrowed to eight bits
  * the broadcast PLMN count widened to eight bits
  * S-NSSAI items padded to an octet between items
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOL = os.path.join(ROOT, "tools", "xnap_asn1.py")

sys.path.insert(0, os.path.join(ROOT, "tools"))

import xnap_asn1  # noqa: E402

# Values, as the tool's own arguments and as pycrate's structure.
CASES = [
    {
        "name": "xnsetup-001-01-22bit",
        "args": dict(mcc="001", mnc="01", gnb_id=0xA1C01, gnb_bits=22,
                     tac=0x000001, sst=0x01, region=0xFF),
        "pycrate": (
            b"\x00\xf1\x10", 0xA1C01, 22, b"\x00\x00\x01", b"\x01", 0xFF,
        ),
    },
    {
        "name": "xnsetup-310-260-22bit",
        "args": dict(mcc="310", mnc="260", gnb_id=0x12345, gnb_bits=22,
                     tac=0xBEEF01, sst=0x55, region=0x07),
        "pycrate": (
            b"\x13\x00\x62", 0x12345, 22, b"\xbe\xef\x01", b"\x55", 0x07,
        ),
    },
    {
        "name": "xnsetup-208-93-32bit",
        "args": dict(mcc="208", mnc="93", gnb_id=0xDEADBEEF, gnb_bits=32,
                     tac=0xFFFFFF, sst=0x7F, region=0x01),
        "pycrate": (
            b"\x02\xf8\x39", 0xDEADBEEF, 32, b"\xff\xff\xff", b"\x7f", 0x01,
        ),
    },
]

# Byte-level defects: (name, hex mutation description, mutation function).
NEGCTL = []


def negctl(name):
    def register(fn):
        NEGCTL.append((name, fn))
        return fn
    return register


@negctl("slice-count-8")
def _slice_count_8(raw):
    """Drop the high octet of the slice count and keep the rest aligned."""
    tai = bytearray(raw[32:45])
    return bytes(raw[:40]) + bytes(tai[:9]) + bytes(tai[11:])


@negctl("broadcast-count-8")
def _broadcast_count_8(raw):
    """Spend a whole octet on the broadcast PLMN count."""
    return raw[:37] + b"\x00" + raw[37:]


@negctl("pad-between-items")
def _pad_between_items(raw):
    """Pad the slice list item to an octet boundary before it ends."""
    return raw[:44] + b"\x00" + raw[44:]


def build_expected(case):
    from pycrate_asn1dir import XnAP

    pdu = XnAP.XnAP_PDU_Descriptions.XnAP_PDU
    plmn, gnb_id, gnb_bits, tac, sst, region = case["pycrate"]
    bits = int(gnb_bits)
    value = {
        "procedureCode": 17,
        "criticality": "reject",
        "value": ("XnSetupRequest", {"protocolIEs": [
            {"id": 4, "criticality": "reject",
             "value": ("AMF-Region-Information",
                       [{"plmn-ID": plmn,
                         "amf-region-id": (int(region), 8)}])},
            {"id": 14, "criticality": "reject",
             "value": ("GlobalNG-RANNode-ID",
                       ("gNB", {"plmn-id": plmn,
                                "gnb-id": ("gnb-ID", (int(gnb_id), bits))}))},
            {"id": 75, "criticality": "reject",
             "value": ("TAISupport-List",
                       [{"tac": tac,
                         "broadcastPLMNs": [
                             {"plmn-id": plmn,
                              "tAISliceSupport-List": [{"sst": sst}]}]}])},
        ]}),
    }
    pdu.set_val(("initiatingMessage", value))
    return pdu.to_aper()


def _scalar(value):
    """pycrate hands back (value, bit length) for constrained INTEGERs."""
    if isinstance(value, tuple):
        return int(value[0])
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, "big")
    return int(value)


def pycrate_reads_back(raw, case):
    """Ask pycrate to read the tool's octets and report what it found."""
    from pycrate_asn1dir import XnAP

    pdu = XnAP.XnAP_PDU_Descriptions.XnAP_PDU
    pdu.from_aper(raw)
    got = pdu.get_val()
    kind, body = got
    if kind != "initiatingMessage":
        return "wrong alternative %r" % (kind,)
    if body.get("procedureCode") != 17:
        return "procedure code %r" % (body.get("procedureCode"),)
    ies = body["value"][1]["protocolIEs"]
    if [item["id"] for item in ies] != [4, 14, 75]:
        return "IE ids %r" % ([item["id"] for item in ies],)
    plmn, gnb_id, gnb_bits, tac, sst, region = case["pycrate"]
    amf = ies[0]["value"][1][0]
    if (amf["plmn-ID"] != plmn
            or _scalar(amf["amf-region-id"]) != int(region)):
        return "AMF region %r" % (amf,)
    # pycrate keeps the type name on every IE value: (name, value), and the
    # GlobalNG-RANNode-ID value is itself a CHOICE tuple.
    if ies[1]["value"][0] != "GlobalNG-RANNode-ID":
        return "IE 14 is %r" % (ies[1]["value"][0],)
    gnb = ies[1]["value"][1][1]
    if gnb["plmn-id"] != plmn:
        return "gNB PLMN %r" % (gnb["plmn-id"],)
    if _scalar(gnb["gnb-id"][1]) != int(gnb_id):
        return "gNB-ID %r" % (gnb["gnb-id"],)
    tai = ies[2]["value"][1][0]
    if tai["tac"] != tac:
        return "TAC %r" % (tai["tac"],)
    got_sst = tai["broadcastPLMNs"][0]["tAISliceSupport-List"][0]["sst"]
    if _scalar(got_sst) != int.from_bytes(sst, "big"):
        return "SST %r" % (got_sst,)
    return None


def _reads_back(case, raw):
    """True when pycrate accepts the octets and finds the case's values."""
    try:
        return pycrate_reads_back(raw, case) is None
    except Exception:
        return False


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--negctl", action="store_true",
                        help="also run the byte-level defects")
    opts = parser.parse_args(argv)

    cases = 0
    mismatches = 0
    for case in CASES:
        args = case["args"]
        mine = xnap_asn1.xnsetup_request(
            args["mcc"], args["mnc"], args["gnb_id"], args["tac"],
            args["sst"], args["region"], args["gnb_bits"])
        if not os.path.exists(TOOL):
            print("UNRUNNABLE\t%s is missing" % TOOL)
            return 2
        try:
            theirs = build_expected(case)
        except Exception as exc:            # noqa: BLE001 -- a broken oracle
            print("UNRUNNABLE\tpycrate refused %s: %s" % (case["name"], exc))
            return 2
        cases += 1
        if mine != theirs:
            mismatches += 1
            where = next((i for i in range(min(len(mine), len(theirs)))
                          if mine[i] != theirs[i]), min(len(mine), len(theirs)))
            print("MISMATCH\t%s octets differ at %d: tool %s / pycrate %s"
                  % (case["name"], where, mine.hex(), theirs.hex()))
        reason = pycrate_reads_back(mine, case)
        if reason is not None:
            mismatches += 1
            print("MISMATCH\t%s pycrate read back %s" % (case["name"], reason))
        # The tool's own decoder is not a referee, but a tool that cannot read
        # what it wrote is broken in a way the octets alone do not show.
        rows = dict(xnap_asn1.decode(mine))
        if rows.get("procedure") != "id-xnSetup":
            mismatches += 1
            print("MISMATCH\t%s tool decoded procedure %r"
                  % (case["name"], rows.get("procedure")))

    print("CASES\t%d" % cases)
    print("MISMATCHES\t%d" % mismatches)
    rc = 0 if mismatches == 0 else 1
    print("RESULT\t%s" % ("AGREE" if rc == 0 else "DISAGREE"))

    if opts.negctl:
        caught = 0
        first = CASES[0]
        raw = xnap_asn1.xnsetup_request(
            first["args"]["mcc"], first["args"]["mnc"], first["args"]["gnb_id"],
            first["args"]["tac"], first["args"]["sst"], first["args"]["region"],
            first["args"]["gnb_bits"])
        for name, mutate in NEGCTL:
            broken = mutate(raw)
            if broken == raw:
                print("NEGCTL\tMISSED\t%s did not change the octets" % name)
                continue
            if _reads_back(first, broken):
                print("NEGCTL\tMISSED\t%s still reads back as the same "
                      "message" % name)
            else:
                caught += 1
                print("NEGCTL\tCAUGHT\t%s" % name)
        print("NEGCTL\t%d/%d caught" % (caught, len(NEGCTL)))
        if caught != len(NEGCTL):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
