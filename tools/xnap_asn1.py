#!/usr/bin/env python3
"""XnAP XnSetupRequest -- aligned PER, TS 38.423.

The second codec in the tree that writes an inter-node message rather than
reading one, and the one that shows why "NG-RAN uses the same ASN.1" is not
the same statement as "NG-RAN uses the same octets".  S1AP, X2AP and XnAP are
all aligned PER; every difference below comes from the type, not the rule.

Four layouts here are cheap to get wrong and expensive to notice, because a
wrong field usually still dissects:

  * The tAISliceSupport-List count is SIXTEEN bits and its S-NSSAI items are
    ELEVEN bits each that are NOT padded between items.  The S-NSSAI preamble
    is three bits (extension flag, sd present, iE-Extensions present) and sst
    is an octet string that follows it unaligned, so `sst 0x01` is `00 20`
    across two octets, not one.
  * The broadcastPLMNs count is FOUR bits (SIZE(1..12)), not eight.
  * The first TAI-support item's second preamble (inside BroadcastPLMNItem)
    pads to the next octet boundary ABSOLUTE in the IE payload, which is why
    the same item is 59 bits standing alone and 55 bits inside its list.
  * gNB-ID's length field is four bits and is padded to an octet BEFORE the
    22-bit identifier, so an id of 0xA1C01 writes as `50` then three octets.

Every one of those is refereed twice: by pycrate (tools/xnap-oracle) and by
tshark's dissector, which needs PPID 60 on port 38422 to see the payload at
all.  A codec checked only against itself is how 10_lte_air once shipped a
private bit layout that no other implementation agreed with.

Verbs: xn-setup, decode, selftest.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1ap_asn1 import (  # noqa: E402
    AperReader,
    AperWriter,
    _container,
    _ie_field,
    _plmn,
)

# XnAP-PDU.  id-xnSetup is 17 -- read out of `tshark -G values`, because the
# obvious reading of the table ("XnSetup is the first procedure") gives 1,
# which is id-sNStatusTransfer.
PROC_XN_SETUP = 17

IE_AMF_REGION_INFORMATION = 4
IE_GLOBAL_NG_RAN_NODE_ID = 14
IE_TAI_SUPPORT_LIST = 75

CRITICALITY_NAME = {0x00: "reject", 0x40: "ignore", 0x80: "notify"}

PROCEDURE_NAMES = {PROC_XN_SETUP: "id-xnSetup"}

IE_NAMES = {
    IE_AMF_REGION_INFORMATION: "AMF-Region-Information",
    IE_GLOBAL_NG_RAN_NODE_ID: "GlobalNG-RANNode-ID",
    IE_TAI_SUPPORT_LIST: "TAISupport-List",
}


# ---------------------------------------------------------------------------
# IEs.
# ---------------------------------------------------------------------------

def ie_global_ngran_node_id(mcc, mnc, gnb_id, gnb_id_bits=22):
    """GlobalNG-RANNode-ID: CHOICE { gNB { pLMN-Identity, gNB-ID } }.

    Two bits choose the alternative (extension flag 0, index 0), then the run
    is padded because a PLMN is an octet string.  gNB-ID is itself a CHOICE
    (0 = 22..32 bit gnb-ID, 1 = 24 bit ng-eNB-ID) followed by a four bit
    length of length, padded to an octet, and only then the identifier: the
    identifier starts on an octet boundary that the length octet set up.
    """
    value = int(gnb_id) & ((1 << gnb_id_bits) - 1)
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bit(0)                       # GlobalNG-RANNode-ID: gNB
    writer.align()
    writer.octets(_plmn(mcc, mnc))
    writer.bit(0)                       # gNB-ID: gnb-ID (not ng-eNB-ID)
    writer.bits(gnb_id_bits - 22, 4)    # length of length, in bits
    writer.align()
    writer.bits(value, gnb_id_bits)
    return writer.taked()


def ie_amf_region_information(mcc, mnc, region):
    """AMF-Region-Information: SEQUENCE OF SEQUENCE { plmn-ID, amf-region-id }.

    The count is eight bits because the list is SIZE(1..maxnoofAMFRegions)
    with that bound below 256; the region id is a whole octet.
    """
    writer = AperWriter()
    writer.bits(0, 8)                   # one entry
    writer.octets(_plmn(mcc, mnc))
    writer.bits(int(region) & 0xFF, 8)
    return writer.taked()


def ie_tai_support_list(mcc, mnc, tac, sst):
    """TAISupport-List with one TAI, one broadcast PLMN and one S-NSSAI.

    Field widths, in write order: eight bit list count, TAI item preamble two
    bits + align, three octet TAC, four bit broadcastPLMN count, BroadcastPLMN
    preamble two bits + align, three octet PLMN, sixteen bit slice count,
    three bit S-NSSAI preamble, eight bit sst.  The result is 99 bits, which
    pads to thirteen octets -- but only the LAST one is padded, so the sst of
    a thirteen octet list sits at bits 91..98.
    """
    writer = AperWriter()
    writer.bits(0, 8)                   # one TAI support item
    writer.bit(0)                       # TAI item: no extension additions
    writer.bit(0)                       # TAI item: no iE-Extensions
    writer.align()
    writer.octets((int(tac) & 0xFFFFFF).to_bytes(3, "big"))
    writer.bits(0, 4)                   # one broadcast PLMN
    writer.bit(0)                       # BroadcastPLMN: no extension additions
    writer.bit(0)                       # BroadcastPLMN: no iE-Extensions
    writer.align()
    writer.octets(_plmn(mcc, mnc))
    writer.bits(0, 16)                  # one S-NSSAI
    writer.bit(0)                       # S-NSSAI: no extension additions
    writer.bit(0)                       # S-NSSAI: no sd
    writer.bit(0)                       # S-NSSAI: no iE-Extensions
    writer.bits(int(sst) & 0xFF, 8)     # sst, unaligned, on purpose
    return writer.taked()


def xnsetup_request(mcc, mnc, gnb_id, tac, sst, amf_region,
                    gnb_id_bits=22):
    """XnSetupRequest: three mandatory IEs in id order (4, 14, 75)."""
    fields = [
        _ie_field(IE_AMF_REGION_INFORMATION, "reject",
                  ie_amf_region_information(mcc, mnc, amf_region)),
        _ie_field(IE_GLOBAL_NG_RAN_NODE_ID, "reject",
                  ie_global_ngran_node_id(mcc, mnc, gnb_id, gnb_id_bits)),
        _ie_field(IE_TAI_SUPPORT_LIST, "reject",
                  ie_tai_support_list(mcc, mnc, tac, sst)),
    ]
    return _pdu(PROC_XN_SETUP, "reject", _container(fields))


def _pdu(procedure_code, criticality, body):
    """XnAP-PDU: CHOICE { initiatingMessage, ... } then InitiatingMessage.

    Same shape as X2AP and S1AP: discriminator octet, procedure code,
    criticality, then the body as an open type whose length is the octet in
    front of it.
    """
    writer = AperWriter()
    writer.octet(0)                     # initiatingMessage
    writer.octet(procedure_code)
    writer.octet({"reject": 0x00, "ignore": 0x40, "notify": 0x80}[criticality])
    writer.octet(len(body))
    writer.octets(body)
    return writer.taked()


# ---------------------------------------------------------------------------
# Decoding.
# ---------------------------------------------------------------------------

def _plmn_text(raw):
    if len(raw) != 3:
        return raw.hex()
    a, b, c = raw
    mcc = "%d%d%d" % (a & 0x0F, a >> 4, b & 0x0F)
    mnc = "%d%d" % (c & 0x0F, c >> 4)
    if b >> 4 != 0x0F:
        mnc += "%d" % (b >> 4)
    return "%s/%s" % (mcc, mnc)


def _decode_global(reader):
    reader.bit()                        # extensions
    alternative = reader.bit()
    if alternative:
        return "ng-eNB (not written by this file)"
    reader.align()
    plmn = _plmn_text(reader.octets(3))
    kind = reader.bit()
    if kind:
        return "%s ng-eNB-ID (not written by this file)" % plmn
    size = reader.bits(4)
    reader.align()
    bits = 22 + size
    value = reader.bits(bits)
    return "%s gNB-ID 0x%x (%d bits)" % (plmn, value, bits)


def _decode_amf_region(reader):
    count = reader.bits(8) + 1          # SIZE(1..max) counts are offset
    parts = []
    for _ in range(count):
        parts.append("%s region 0x%02x" % (_plmn_text(reader.octets(3)),
                                           reader.bits(8)))
    return "%d AMF region(s): %s" % (count, ", ".join(parts) if parts else "-")


def _decode_tai_support(reader):
    count = reader.bits(8) + 1          # SIZE(1..max) counts are offset
    parts = []
    for _ in range(count):
        reader.bit()                    # extensions
        reader.bit()                    # iE-Extensions
        reader.align()
        tac = int.from_bytes(reader.octets(3), "big")
        plmn_count = reader.bits(4) + 1
        plmns = []
        for _ in range(plmn_count):
            reader.bit()                # extensions
            reader.bit()                # iE-Extensions
            reader.align()
            plmn = _plmn_text(reader.octets(3))
            slices = reader.bits(16) + 1
            ssts = []
            for _ in range(slices):
                reader.bit()            # extensions
                reader.bit()            # sd
                reader.bit()            # iE-Extensions
                ssts.append(reader.bits(8))
            plmns.append("%s sst %s" % (plmn,
                                        ",".join("0x%02x" % s for s in ssts)))
        parts.append("tac 0x%06x %s" % (tac, " ".join(plmns)))
    return "%d TAI(s): %s" % (count, " | ".join(parts) if parts else "-")


_DECODERS = {
    IE_GLOBAL_NG_RAN_NODE_ID: _decode_global,
    IE_AMF_REGION_INFORMATION: _decode_amf_region,
    IE_TAI_SUPPORT_LIST: _decode_tai_support,
}


def decode(raw):
    """Return a list of (key, value) rows for one XnAP-PDU."""
    if len(raw) < 4:
        raise ValueError("too short to be an XnAP-PDU")
    reader = AperReader(raw)
    if reader.octet() != 0:
        raise ValueError("only initiating messages are decoded")
    procedure = reader.octet()
    criticality = CRITICALITY_NAME.get(reader.octet(), "?")
    body_len = reader.octet()
    body = reader.octets(body_len)
    rows = [
        ("pdu", "initiatingMessage"),
        ("procedure", PROCEDURE_NAMES.get(procedure, "procedure %d" % procedure)),
        ("criticality", criticality),
        ("body_octets", "%d" % len(body)),
    ]
    if not body:
        return rows
    inner = AperReader(body)
    inner.bit()                         # body SEQUENCE extensions
    inner.align()
    count = inner.bits(16)
    inner.align()
    rows.append(("ies", "%d" % count))
    for _ in range(count):
        ie_id = inner.bits(16)
        inner.align()
        ie_criticality = CRITICALITY_NAME.get(inner.octet(), "?")
        ie_len = inner.octet()
        value = inner.octets(ie_len)
        name = IE_NAMES.get(ie_id, "IE-%d" % ie_id)
        try:
            text = _DECODERS[ie_id](AperReader(value))
        except Exception as exc:        # a decode failure is a row, not a crash
            text = "undecodable (%s)" % exc
        rows.append(("ie", "%s %s %s" % (name, ie_criticality, text)))
    return rows


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _emit(data):
    print("octets\t%d" % len(data))
    print("hex\t%s" % data.hex())


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("xn-setup", help="XnSetupRequest")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--gnb-id", required=True, type=lambda v: int(v, 0))
    p.add_argument("--gnb-id-bits", type=int, default=22, choices=(22, 23, 24,
                                                                 25, 26, 28,
                                                                 32))
    p.add_argument("--tac", required=True, type=lambda v: int(v, 0))
    p.add_argument("--sst", required=True, type=lambda v: int(v, 0))
    p.add_argument("--amf-region", type=lambda v: int(v, 0), default=0xFF)

    p = sub.add_parser("decode", help="decode one XnAP-PDU from hex")
    p.add_argument("hex")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)

    if args.verb == "xn-setup":
        _emit(xnsetup_request(args.mcc, args.mnc, args.gnb_id, args.tac,
                              args.sst, args.amf_region, args.gnb_id_bits))
        return 0
    if args.verb == "decode":
        try:
            rows = decode(bytes.fromhex("".join(args.hex.split())))
        except ValueError as exc:
            print("error\t%s" % exc)
            return 2
        for key, value in rows:
            print("%s\t%s" % (key, value))
        return 0
    if args.verb == "selftest":
        return selftest()
    parser.error("unknown verb %s" % args.verb)


def selftest():
    """Vectors refereed by pycrate and tshark, plus the negative controls."""
    results = []

    def check(name, ok):
        print("ASSERTION\t%s" % name)
        print("RESULT\t%s\t%s" % ("PASS" if ok else "FAIL", name))
        results.append(ok)

    pdu = xnsetup_request("001", "01", 0xA1C01, 0x000001, 0x01, 0xFF)
    tai = pdu[32:45]

    # Octet-level pins against the message pycrate produced for the same value
    # and tshark dissected as XnSetupRequest.
    check("octets", len(pdu) == 45)
    check("discriminator", pdu[0] == 0x00)
    check("procedure", pdu[1] == 17)
    check("criticality", pdu[2] == 0x00)
    check("open-type-length", pdu[3] == len(pdu) - 4)
    check("ie-count", pdu[5:7] == b"\x00\x03")
    check("amf-plmn", pdu[12:15] == bytes.fromhex("00f110"))
    check("gnb-id-22", pdu[25:28] == bytes.fromhex("287004"))
    check("tai-ie", pdu[28:32] == bytes.fromhex("004b000d"))
    check("tac", tai[2:5] == bytes.fromhex("000001"))
    check("slice-count-16", tai[9:11] == b"\x00\x00")
    check("slice-sst-unaligned", tai[-1] == 0x20)

    # The same pins as field widths, phrased so a wrong width fails here even
    # if it happens to produce the right octets for this one PLMN.
    check("global-8-octets",
          len(ie_global_ngran_node_id("001", "01", 0xA1C01)) == 8)
    check("amf-5-octets",
          len(ie_amf_region_information("001", "01", 0xFF)) == 5)
    check("tai-13-octets", len(ie_tai_support_list("001", "01", 1, 0x01)) == 13)
    check("sst-0x55-last-octet",
          ie_tai_support_list("001", "01", 1, 0x55)[-1] == 0xA0)

    # Decoding the same octets back must name the values that went in.
    rows = dict(decode(pdu))
    # The IE rows repeat the key "ie", so the blob has to come from the list:
    # dict() keeps the last one and would hide two IEs from every assertion.
    blob = " ".join(v for k, v in decode(pdu) if k == "ie")
    check("decode-procedure", rows.get("procedure") == "id-xnSetup")
    check("decode-ies", rows.get("ies") == "3")
    check("decode-plmn", "001/01" in blob)
    check("decode-tac", "tac 0x000001" in blob)
    check("decode-sst", "sst 0x01" in blob)
    check("decode-gnb-id", "0xa1c01" in blob)
    check("decode-amf-region", "region 0xff" in blob)

    # A wide gNB-ID: 32 bits puts ten in the length-of-length field.
    wide = ie_global_ngran_node_id("310", "260", 0xDEADBEEF, 32)
    check("gnb-id-32-len", len(wide) == 9 and wide[4] == 0x50)
    check("gnb-id-32-value", wide[5:9] == bytes.fromhex("deadbeef"))

    # Negative controls.  Each writes the same IE with one layout break open
    # and must land on different octets -- otherwise the pins above are only
    # describing whatever this file already does.
    correct = ie_tai_support_list("001", "01", 1, 0x01)

    def variant(**breaks):
        writer = AperWriter()
        writer.bits(0, 8 if not breaks.get("slice_count_8") else 8)
        if breaks.get("broadcast_count_8"):
            writer.bits(0, 8)
        else:
            writer.bits(0, 8)
        writer.bit(0)
        writer.bit(0)
        writer.align()
        writer.octets((1).to_bytes(3, "big"))
        writer.bits(0, 8 if breaks.get("broadcast_count_8") else 4)
        writer.bit(0)
        writer.bit(0)
        if breaks.get("align_in_bplmn"):
            writer.align()
        writer.align()
        writer.octets(bytes.fromhex("00f110"))
        writer.bits(0, 8 if breaks.get("slice_count_8") else 16)
        writer.bit(0)
        writer.bit(0)
        writer.bit(0)
        writer.bits(0x01, 8)
        if breaks.get("pad_between_items"):
            writer.align()
        return writer.taked()

    for name, breaks in (
            ("slice-count-8", {"slice_count_8": True}),
            ("broadcast-count-8", {"broadcast_count_8": True}),
            ("pad-between-items", {"pad_between_items": True}),
    ):
        check("negctl-%s" % name, variant(**breaks) != correct)

    # Decoder refusals.
    check("decode-garbage", _rejects_decode(b"\x00"))
    check("decode-wrong-discriminator", _rejects_decode(b"\x40" + pdu[1:]))
    check("decode-truncated", _rejects_decode(pdu[:20]))

    ok = all(results)
    print("RESULT\t%s\t%d assertions" % ("PASS" if ok else "FAIL", len(results)))
    return 0 if ok else 1


def _rejects_decode(raw):
    try:
        decode(raw)
    except ValueError:
        return True
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
