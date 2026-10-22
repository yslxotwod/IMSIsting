#!/usr/bin/env python3
"""Independent encoder/decoder for the UTRAN RRC messages modules/08_umts_air.sh builds.

Why this file exists
--------------------
The module states, in comments, that its octets are placed per TS 25.331's
unaligned PER rules. A comment is not evidence, and neither is a module agreeing
with its own length table: an encoder and its table are wrong together. Two
independent readers are available on this machine:

  * Wireshark's RRC dissector, used by tools/check-umts-rrc.sh, which proves the
    octets are a real message on the air; and
  * pycrate's generated transcription of the TS 25.331 ASN.1
    (pycrate_asn1dir.RRC3G), used here.

This script makes the second comparison explicit and adds the direction the
dissector cannot: pycrate *decodes* the module's bits back into a value tree, so
each field below is asserted against the ASN.1, not against a byte string
someone once observed. It checks, for RRC CONNECTION SETUP, RRC CONNECTION
REJECT and PAGING TYPE 1:

  1. bits   -- pycrate's encoding of the same value is bit-identical to the
               module's, to the last message bit (not merely the last octet);
  2. read   -- pycrate decodes the module's octets and reports the intended
               field values;
  3. type   -- the module's own --parse-rrc names the same message type pycrate
               decodes, so the two directions of the module agree;
  4. negate -- the top-level CHOICE index moved by hand changes the type
               pycrate decodes, which shows the index is what carries it.

What this does NOT cover, stated plainly:
  * the ON-AIR behaviour: this compares an encoder and a decoder, not a UE;
  * pycrate's own fidelity to TS 25.331. pycrate is the independent
    implementation here; if its transcription is wrong, both sides are wrong
    together. That risk is why tools/check-umts-rrc.sh does not rely on pycrate
    at all and asks Wireshark instead;
  * every field the module refuses to encode (extension chains, the 10 optional
    r3-IEs of the setup, redirectionInfo, ciphering, MAC-I authenticity).

Exit codes: 0 all checks pass, 1 a check failed, 2 pycrate is not available.
"""

import os
import subprocess
import sys

try:
    from pycrate_asn1dir import RRC3G as R
    from pycrate_asn1rt.utils import pack_val
except ImportError:
    print("SKIP\tpycrate is not importable: the ASN.1 transcription is the "
          "second opinion here, so nothing is claimed")
    sys.exit(2)

C = R.Class_definitions

CHECKS = 0
FAILS = 0


def chk(name, got, want):
    global CHECKS, FAILS
    CHECKS += 1
    if got == want:
        print("check\t%s\tPASS" % name)
    else:
        FAILS += 1
        print("check\t%s\tFAIL\tgot=%r want=%r" % (name, got, want))


def encode(typ, value):
    """Return (hex, bits) for one pycrate PDU value."""
    typ.set_val(value)
    buf, n = pack_val(*typ._to_per())
    return buf[:(n + 7) // 8].hex(), n


def bits_of(hexstr, nbits):
    return "".join(format(b, "08b") for b in bytes.fromhex(hexstr))[:nbits]


def module(*args):
    """Run the module and return its stdout."""
    out = subprocess.run(["bash", MODULE] + list(args),
                         capture_output=True, text=True)
    return out.stdout


def row(text, key):
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) >= 2 and f[0] == key:
            return f[1]
    return ""


def module_build(verb, conf):
    return module(verb, conf)


# The values below mirror the documentation in the module's usage block and are
# the same ones tools/check-umts-rrc.sh passes explicitly, so a change of
# default in one place cannot drag the other along silently.
LAI = {"plmn-Identity": {"mcc": [0, 0, 1], "mnc": [0, 1]}, "lac": (0x0001, 16)}
IDENT = ("tmsi-and-LAI", {"tmsi": (0x12345678, 32), "lai": LAI})
TFS = {
    "tti": ("tti20", [{"rlc-Size": ("octetModeType1", ("sizeType1", 0)),
                       "numberOfTbSizeList": [("large", 42)],
                       "logicalChannelList": ("configured", 0)}]),
    "semistaticTF-Information": {"channelCodingType": ("turbo", 0),
                                 "rateMatchingAttribute": 100,
                                 "crc-Size": "crc16"},
}


def rb_mapping(i):
    return {"ul-LogicalChannelMappings": ("oneLogicalChannel", {
        "ul-TransportChannelType": ("dch", 1),
        "logicalChannelIdentity": i,
        "rlc-SizeList": ("configured", 0),
        "mac-LogicalChannelPriority": i}),
        "dl-LogicalChannelMappingList": [
            {"dl-TransportChannelType": ("dch", 1),
             "logicalChannelIdentity": i}]}


SRB1 = {"rb-Identity": 1, "rlc-InfoChoice": ("rlc-Info", {
    "ul-RLC-Mode": ("ul-AM-RLC-Mode", {
        "transmissionRLC-Discard": ("noDiscard", "dat1"),
        "transmissionWindowSize": "tw2047",
        "timerRST": "tr500",
        "max-RST": "rst1"}),
    "dl-RLC-Mode": ("dl-AM-RLC-Mode", {
        "inSequenceDelivery": True,
        "receivingWindowSize": "rw2047",
        "dl-RLC-StatusInfo": {"missingPDU-Indicator": False}})}),
    "rb-MappingInfo": [rb_mapping(1)]}

SETUP = ("r3", {"rrcConnectionSetup-r3": {
    "initialUE-Identity": IDENT,
    "rrc-TransactionIdentifier": 0,
    "new-U-RNTI": {"srnc-Identity": (0x123, 12), "s-RNTI": (0x12345, 20)},
    "rrc-StateIndicator": "cell-DCH",
    "utran-DRX-CycleLengthCoeff": 6,
    "srb-InformationSetupList": [SRB1] + [
        {"rb-Identity": i, "rlc-InfoChoice": ("same-as-RB", 1),
         "rb-MappingInfo": [rb_mapping(i)]} for i in (2, 3, 4)],
    "ul-AddReconfTransChInfoList": [{
        "ul-TransportChannelType": "dch",
        "transportChannelIdentity": 1,
        "transportFormatSet": ("dedicatedTransChTFS", TFS)}],
    "dl-AddReconfTransChInfoList": [{
        "dl-TransportChannelType": "dch",
        "dl-transportChannelIdentity": 1,
        "tfs-SignallingMode": ("explicit-config", ("dedicatedTransChTFS", TFS))}]}})

REJECT = ("r3", {"rrcConnectionReject-r3": {
    "initialUE-Identity": IDENT,
    "rrc-TransactionIdentifier": 0,
    "rejectionCause": "congestion",
    "waitTime": 8}})

PAGING = {"message": ("pagingType1", {
    "pagingRecordList": [("cn-Identity", {
        "pagingCause": "terminatingConversationalCall",
        "cn-DomainIdentity": "cs-domain",
        "cn-pagedUE-Identity": ("tmsi-GSM-MAP", (0x12345678, 32))})],
    "bcch-ModificationInfo": {"mib-ValueTag": 1}})}

# One spec per verb: the module refuses a key its verb does not read, so a
# shared spec would be refused rather than silently narrowed.
CONF_SETUP = ("tmsi=12345678,lac=0001,mcc=001,mnc=01,txid=0,srnc=123,"
              "srnti=12345,drx=6,state=cell-DCH")
CONF_REJECT = ("tmsi=12345678,lac=0001,mcc=001,mnc=01,txid=0,"
               "cause=congestion,wait=8")
CONF_PAGING = "tmsi=12345678,cause=terminatingConversationalCall,domain=cs,mib=1"


def main():
    global MODULE
    here = os.path.dirname(os.path.abspath(__file__))
    MODULE = os.path.normpath(os.path.join(here, "..", "modules", "08_umts_air.sh"))

    # 1/2. Encode direction, then decode the module's own octets back.
    cases = [
        ("setup", "--build-rrc-setup", C.DL_CCCH_Message,
         {"message": ("rrcConnectionSetup", SETUP)}, CONF_SETUP,
         "rrcConnectionSetup"),
        ("reject", "--build-rrc-reject", C.DL_CCCH_Message,
         {"message": ("rrcConnectionReject", REJECT)}, CONF_REJECT,
         "rrcConnectionReject"),
        ("paging", "--build-paging", C.PCCH_Message, PAGING,
         CONF_PAGING, "pagingType1"),
    ]
    # The catcher's DL DIRECT TRANSFER: the wrapper tshark 4.2.2 cannot read past
    # the transaction identifier. pycrate's transcription of TS 25.331 can decode
    # it, so the claim changes from "derived from the ASN.1, no referee" to a
    # field-by-field comparison against the ASN.1 itself.
    CATCHER = {"message": ("downlinkDirectTransfer", ("r3", {
        "downlinkDirectTransfer-r3": {
            "rrc-TransactionIdentifier": 0,
            "cn-DomainIdentity": "cs-domain",
            "nas-Message": bytes.fromhex("05001801"),
        },
    }))}
    ref_hex, ref_bits = encode(C.DL_DCCH_Message, CATCHER)
    got = module("--catcher-identity", "--identity", "imsi")
    got_hex, got_bits = row(got, "rrc_hex"), row(got, "rrc_bits")
    chk("catcher-dl-dcch-bits-length", got_bits, str(ref_bits))
    chk("catcher-dl-dcch-bits-identical",
        bits_of(got_hex, ref_bits) == bits_of(ref_hex, ref_bits), True)
    chk("catcher-dl-dcch-hex", got_hex, ref_hex)
    C.DL_DCCH_Message.from_uper(bytes.fromhex(got_hex))
    dt = C.DL_DCCH_Message.get_val()["message"]
    chk("catcher-dl-dcch-name", dt[0], "downlinkDirectTransfer")
    dt_r3 = dt[1][1]["downlinkDirectTransfer-r3"]
    chk("catcher-dl-dcch-txid", dt_r3["rrc-TransactionIdentifier"], 0)
    chk("catcher-dl-dcch-domain", dt_r3["cn-DomainIdentity"], "cs-domain")
    chk("catcher-dl-dcch-nas", dt_r3["nas-Message"].hex(), "05001801")

    encoded = {}
    for label, verb, typ, value, conf, want_type in cases:
        ref_hex, ref_bits = encode(typ, value)
        out = module_build(verb, conf)
        got_hex = row(out, "hex")
        got_bits = row(out, "bits")
        chk("%s-bits-length" % label, got_bits, str(ref_bits))
        chk("%s-bits-identical" % label,
            bits_of(got_hex, ref_bits) == bits_of(ref_hex, ref_bits), True)
        # The decode direction reads the module's octets, not pycrate's.
        typ.from_uper(bytes.fromhex(got_hex))
        m = typ
        decoded = m.get_val()
        got_name = decoded["message"][0]
        chk("%s-decodes-to" % label, got_name, want_type)
        encoded[label] = (got_hex, decoded)

    # 3. The module's parser must name the same type pycrate decodes.
    chk("setup-parser-type",
        row(module("--parse-rrc", "dl-ccch:" + encoded["setup"][0]),
            "message_type"), "rrcConnectionSetup")
    chk("reject-parser-type",
        row(module("--parse-rrc", "dl-ccch:" + encoded["reject"][0]),
            "message_type"), "rrcConnectionReject")
    chk("paging-parser-type",
        row(module("--parse-rrc", "pcch:" + encoded["paging"][0]),
            "message_type"), "pagingType1")

    # 2b. Named fields, read out of the decoded tree.
    inner = encoded["setup"][1]["message"][1][1]["rrcConnectionSetup-r3"]
    chk("setup-tmsi", inner["initialUE-Identity"][1]["tmsi"][0], 0x12345678)
    chk("setup-lac", inner["initialUE-Identity"][1]["lai"]["lac"][0], 1)
    chk("setup-mcc", inner["initialUE-Identity"][1]["lai"]["plmn-Identity"]["mcc"],
        [0, 0, 1])
    chk("setup-mnc", inner["initialUE-Identity"][1]["lai"]["plmn-Identity"]["mnc"],
        [0, 1])
    chk("setup-urni", inner["new-U-RNTI"]["s-RNTI"][0], 0x12345)
    chk("setup-state", inner["rrc-StateIndicator"], "cell-DCH")
    chk("setup-drx", inner["utran-DRX-CycleLengthCoeff"], 6)
    chk("setup-srb-count", len(inner["srb-InformationSetupList"]), 4)
    chk("setup-ratematch",
        inner["ul-AddReconfTransChInfoList"][0]["transportFormatSet"][1]
             ["semistaticTF-Information"]["rateMatchingAttribute"], 100)
    inner = encoded["reject"][1]["message"][1][1]["rrcConnectionReject-r3"]
    chk("reject-cause", inner["rejectionCause"], "congestion")
    chk("reject-wait", inner["waitTime"], 8)
    inner = encoded["paging"][1]["message"][1]
    chk("paging-cause",
        inner["pagingRecordList"][0][1]["pagingCause"],
        "terminatingConversationalCall")
    chk("paging-tmsi",
        inner["pagingRecordList"][0][1]["cn-pagedUE-Identity"][1][0], 0x12345678)
    chk("paging-mib", inner["bcch-ModificationInfo"]["mib-ValueTag"], 1)

    # 4. Negation: the setup index 3 moved to 5 (dummy) must decode to another
    # alternative. 0x30 -> 0x50 moves the three index bits and leaves the rest.
    neg = "50" + encoded["setup"][0][2:]
    m = C.DL_CCCH_Message
    try:
        m.from_uper(bytes.fromhex(neg))
        neg_type = m.get_val()["message"][0]
    except Exception:
        neg_type = "<decode error>"
    chk("negate-setup-type", neg_type != "rrcConnectionSetup", True)
    chk("negate-setup-named", neg_type, "dummy")

    print("CHECKS\t%d\t%s" % (CHECKS, "PASS" if FAILS == 0 else "FAILED"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
