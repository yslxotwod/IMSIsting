#!/usr/bin/env python3
"""NGAP codec check against TS 38.413 and pycrate.

tools/ngap_asn1.py writes NGAP octets. NGAP is what a gNB says to an AMF, so
a wrong IE number there is a claim about a subscriber's identity or location
made in the wrong field, and a wrong bit layout is a message that dissects
without an error and means something else. So the tool is checked against the
clause statement and against a second implementation, not against itself.

What the clause says (ETSI TS 138 413 V16.2.0, with X.691 for the encoding):

  §9.1   NGAP-PDU is a CHOICE of initiatingMessage, successfulOutcome,
         unsuccessfulOutcome -- three root alternatives, extensible. APER
         therefore opens it with the extension bit then a two-bit choice
         index, both zero: one octet 0x00.
  §9.1   InitiatingMessage is a SEQUENCE of procedureCode (INTEGER,
         0..255), criticality (ENUMERATED, extensible) and value
         (NGAP-ELEMENTARY-PROCEDURE, an open type). No SEQUENCE preamble:
         there is no extension marker and no OPTIONAL on it.
  §9.3   Criticality is ENUMERATED { reject, ignore, notify, ... }: the
         extension bit is the top bit of the octet and the index sits in the
         two below it, so reject is 0x00, ignore 0x40, notify 0x80.
  §9.3   ProtocolIE-Container is SEQUENCE (SIZE(0..65535)) OF
         ProtocolIE-Field, and the SEQUENCE IS extensible: one preamble bit,
         an alignment, then a SIXTEEN-bit count. A one-octet count parses,
         reports zero IEs and drops the body.
  §9.3   ProtocolIE-Field is SEQUENCE { id INTEGER(0..65535), criticality,
         value (open type) }: no preamble, id in two octets, then the
         criticality octet, then a length determinant and the value.
  §9.3   The IE ids used below: RAN-UE-NGAP-ID 85, AMF-UE-NGAP-ID 10,
         NAS-PDU 38, UEPagingIdentity 115, TAIListForPaging 103.
  X.691 §13.2.2  A constrained INTEGER uses the fewest octets that can hold
         the upper bound and puts the octet count minus one above them, in
         as many bits as that count needs. For 0..4294967295 that is two
         bits; for 0..1099511627775 (the 40-bit AMF UE id) THREE. This is
         the rule that differs from S1AP's 32-bit fields, and the one a
         shared helper would hide.
  X.691 §13.2  TAIListForPaging is SEQUENCE (SIZE(1..16)) OF TAI: the count
         is four bits (value minus the lower bound 1) and the first TAI's
         iE-Extensions bit shares that octet -- aligning first spends an
         octet on zeroes.
  X.691 §14    A TAI is { pLMNIdentity (3 octets), tAC OCTET STRING(SIZE(3)),
         iE-Extensions OPTIONAL }. The TAC is THREE octets in 5G where S1AP
         has two.
  X.691 §14    UEPagingIdentity is an extensible CHOICE whose root holds
         fiveG-S-TMSI: extension bit, choice index, then that SEQUENCE's
         iE-Extensions bit, then aMFSetID (10 bits) and aMFPointer (6 bits)
         with no alignment between them, then an alignment and the 4-octet
         5G-TMSI.

pycrate 0.8.1's pycrate_asn1dir.NGAP is the second implementation: it is
given the same values through its own structure and must produce the same
octets, and it must read the tool's octets back to those values.

Four defects put back into a scratch copy of the tool must each make this
check fail:
  * the INTEGER length field widened to the S1AP rule (two bits everywhere)
  * the ProtocolIE-Container count narrowed to one octet
  * the TAI's TAC narrowed to two octets
  * the TAI list's preamble bit moved below the alignment

usage: check_ngap_codec.py [--tool PATH] [--negctl] [--verbose]
"""
import argparse
import os
import subprocess
import sys
import tempfile

TOOL = "/home/ysl/IMSIsting/tools/ngap_asn1.py"

# The clause statement above, as values. Transcribed from TS 38.413, not read
# from the tool: the point of the comparison is that the two were written
# apart.
NAS_UL = "7e0041012e0100"   # 5G Registration request
NAS_DL = "7e005b01"         # 5G Identity request
CASES = [
    {
        "name": "initial-ue",
        "argv": ["initial-ue", "--ran-ue-id", "1", "--nas", NAS_UL],
        "pycrate": (15, "reject", "InitialUEMessage", [
            (85, "reject", "RAN-UE-NGAP-ID", 1),
            (38, "reject", "NAS-PDU", bytes.fromhex(NAS_UL)),
        ]),
    },
    {
        "name": "downlink-nas",
        "argv": ["downlink-nas", "--amf-ue-id", "256", "--ran-ue-id", "1",
                 "--nas", NAS_DL],
        "pycrate": (4, "reject", "DownlinkNASTransport", [
            (10, "reject", "AMF-UE-NGAP-ID", 256),
            (85, "reject", "RAN-UE-NGAP-ID", 1),
            (38, "reject", "NAS-PDU", bytes.fromhex(NAS_DL)),
        ]),
    },
    {
        "name": "paging",
        "argv": ["paging", "--amf-set-id", "1", "--amf-pointer", "0",
                 "--tmsi", "0a0b0c0d", "--tai", "001/01/000001"],
        "pycrate": (24, "ignore", "Paging", [
            (115, "ignore", "UEPagingIdentity", ("fiveG-S-TMSI", {
                # pycrate takes a SIZE-constrained BIT STRING as
                # (value, bit length) -- an int alone is rejected.
                "aMFSetID": (1, 10),
                "aMFPointer": (0, 6),
                "fiveG-TMSI": bytes.fromhex("0a0b0c0d"),
            })),
            (103, "ignore", "TAIListForPaging", [
                {"tAI": {"pLMNIdentity": b"\x00\xf1\x10",
                         "tAC": b"\x00\x00\x01"}},
            ]),
        ]),
    },
    {
        "name": "initial-ue-located",
        "argv": ["initial-ue", "--ran-ue-id", "1", "--nas", NAS_UL,
                 "--nci", "0x123456789", "--tac", "000001",
                 "--cause", "mo-Data"],
        "pycrate": (15, "reject", "InitialUEMessage", [
            (85, "reject", "RAN-UE-NGAP-ID", 1),
            (38, "reject", "NAS-PDU", bytes.fromhex(NAS_UL)),
            (121, "reject", "UserLocationInformation",
             ("userLocationInformationNR", {
                 # A SIZE-constrained BIT STRING takes (value, bit length).
                 "nR-CGI": {"pLMNIdentity": b"\x00\xf1\x10",
                            "nRCellIdentity": (0x123456789, 36)},
                 "tAI": {"pLMNIdentity": b"\x00\xf1\x10",
                         "tAC": b"\x00\x00\x01"},
             })),
            (90, "ignore", "RRCEstablishmentCause", "mo-Data"),
        ]),
    },
    {
        "name": "ng-setup",
        "argv": ["ng-setup", "--plmn", "001/01", "--gnb-id", "0xA1C01",
                 "--node-name", "LabGnb", "--tac", "000001"],
        "pycrate": (21, "reject", "NGSetupRequest", [
            (27, "reject", "GlobalRANNodeID",
             ("globalGNB-ID", {
                 "pLMNIdentity": b"\x00\xf1\x10",
                 "gNB-ID": ("gNB-ID", (0x0A1C01, 22)),
             })),
            (82, "ignore", "RANNodeName", "LabGnb"),
            (102, "reject", "SupportedTAList", [
                {"tAC": b"\x00\x00\x01",
                 "broadcastPLMNList": [
                     {"pLMNIdentity": b"\x00\xf1\x10",
                      "tAISliceSupportList": [
                          {"s-NSSAI": {"sST": b"\x01"}},
                      ]},
                 ]},
            ]),
        ]),
    },
    {
        # A 32-bit identity, because a 22-bit one cannot tell a four-bit
        # length-of-length from a two-bit one: both spend the octet as 00.
        "name": "ng-setup-wide-id",
        "argv": ["ng-setup", "--plmn", "001/01", "--gnb-id", "0xFFFFFFFF",
                 "--gnb-id-bits", "32", "--node-name", "LabGnb",
                 "--tac", "000001"],
        "pycrate": (21, "reject", "NGSetupRequest", [
            (27, "reject", "GlobalRANNodeID",
             ("globalGNB-ID", {
                 "pLMNIdentity": b"\x00\xf1\x10",
                 "gNB-ID": ("gNB-ID", (0xFFFFFFFF, 32)),
             })),
            (82, "ignore", "RANNodeName", "LabGnb"),
            (102, "reject", "SupportedTAList", [
                {"tAC": b"\x00\x00\x01",
                 "broadcastPLMNList": [
                     {"pLMNIdentity": b"\x00\xf1\x10",
                      "tAISliceSupportList": [
                          {"s-NSSAI": {"sST": b"\x01"}},
                      ]},
                 ]},
            ]),
        ]),
    },
]


def load_pycrate():
    from pycrate_asn1dir import NGAP
    return NGAP


def pycrate_encode(NGAP, procedure, criticality, typename, fields):
    """Set the PDU inside pycrate's own structures and encode aligned PER."""
    descriptions = NGAP.NGAP_PDU_Descriptions
    ies = [{"id": ie_id, "criticality": crit, "value": (name, value)}
           for ie_id, crit, name, value in fields]
    body = {"protocolIEs": ies}
    pdu = descriptions.NGAP_PDU
    pdu.set_val(("initiatingMessage", {
        "procedureCode": procedure,
        "criticality": criticality,
        "value": (typename, body),
    }))
    return pdu.to_aper()


def tool_run(tool, argv):
    """Ask the tool for one message; return (hextext, stderr)."""
    proc = subprocess.run([sys.executable, tool] + argv,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("tool failed: %s" % (proc.stderr.strip() or proc.stdout.strip()))
    for line in proc.stdout.splitlines():
        if line.startswith("hex\t"):
            return line.split("\t", 1)[1]
    raise RuntimeError("tool printed no hex: %r" % proc.stdout)


def pycrate_decode_ie_values(NGAP, raw, case):
    """Read the tool's octets with pycrate and return the IE values it sees."""
    descriptions = NGAP.NGAP_PDU_Descriptions
    pdu = descriptions.NGAP_PDU
    pdu.from_aper(raw)
    value = pdu.get_val()
    kind, message = value[0], value[1]
    if kind != "initiatingMessage":
        raise RuntimeError("pycrate read %r, not an initiatingMessage" % (kind,))
    fields = message["value"][1]["protocolIEs"]
    rows = []
    for field in fields:
        typename, body = field["value"]
        rows.append((field["id"], field["criticality"], typename,
                     _plain(body)))
    return message["procedureCode"], rows


def _plain(value):
    """Flatten pycrate's value shapes to something comparable."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_plain(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


def expected_rows(case):
    rows = []
    for ie_id, crit, name, value in case["pycrate"][3]:
        rows.append((ie_id, crit, name, _spec_value(name, value)))
    return rows


def _spec_value(name, value):
    """The value pycrate must hand back for an IE, in its own read shapes."""
    if name == "RAN-UE-NGAP-ID":
        return value
    if name == "AMF-UE-NGAP-ID":
        return value
    if name == "NAS-PDU":
        return bytes(value)
    if name == "UEPagingIdentity":
        choice, body = value
        return (choice, {
            "aMFSetID": body["aMFSetID"],
            "aMFPointer": body["aMFPointer"],
            "fiveG-TMSI": body["fiveG-TMSI"],
        })
    if name == "TAIListForPaging":
        return [{"tAI": {"pLMNIdentity": item["tAI"]["pLMNIdentity"],
                         "tAC": item["tAI"]["tAC"]}} for item in value]
    return value


NEGCTL = [
    # (name, what it claims, old text, new text, case it must break)
    ("integer-length-is-s1ap-width",
     "the INTEGER length field uses S1AP's two bits everywhere",
     "    length_bits = (widest - 1).bit_length()",
     "    length_bits = 2",
     "downlink-nas"),
    ("container-count-is-one-octet",
     "the ProtocolIE-Container count narrowed to eight bits",
     "    writer.constrained_count(len(ie_fields), 16)",
     "    writer.constrained_count(len(ie_fields), 8)",
     "initial-ue"),
    ("tac-is-two-octets",
     "the 5G TAC narrowed to the 4G width",
     '        if len(raw_tac) != 3:\n            raise ValueError("a 5G TAC is three octets, got %r" % (tac,))',
     '        if len(raw_tac) != 2:\n            raw_tac = raw_tac[:2]',
     "paging"),
    ("tai-list-bit-written-after-align",
     "the first TAI's iE-Extensions bit moved below the alignment, so the"
     " 4-bit count gets an octet to itself",
     "    writer.bit(0)                       # the first TAI's iE-Extensions bit\n"
     "    writer.align()                      # count and that bit share one octet",
     "    writer.align()\n"
     "    writer.bit(0)",
     "paging"),
    # The four below break what this turn added: the shared preamble octet,
    # the establishment cause's four-bit index, the name's extension bit
    # ordering, the unaligned SST and the gNB-ID width field.
    ("location-preamble-aligned-between-the-two-runs",
     "the NR-CGI preamble aligned on its own octet instead of sharing one"
     " with the ULI preamble",
     "    _absent(writer, 2)                  # timeStamp and iE-Extensions absent\n"
     "    _absent(writer, 1)                  # NR-CGI: iE-Extensions absent\n"
     "    writer.align()",
     "    _absent(writer, 2)                  # timeStamp and iE-Extensions absent\n"
     "    writer.align()\n"
     "    _absent(writer, 1)                  # NR-CGI: iE-Extensions absent\n"
     "    writer.align()",
     "initial-ue-located"),
    ("cause-index-is-two-bits",
     "the establishment cause's index narrowed from four bits to two",
     "    writer.bits(CAUSES.index(cause), 4)",
     "    writer.bits(CAUSES.index(cause), 2)",
     "initial-ue-located"),
    ("ran-node-name-length-before-extension",
     "the name's length octet placed before the size constraint's extension"
     " bit, so a reader sees 05 00 rather than 02 80",
     "    writer.bit(0)                       # the size constraint's extension bit\n"
     "    writer.bits(len(raw) - 1, 8)",
     "    writer.bits(len(raw) - 1, 8)\n"
     "    writer.bit(0)                       # the size constraint's extension bit",
     "ng-setup"),
    ("sst-aligned-as-its-own-octet",
     "the S-NSSAI SST written as an aligned octet, spending the two octets of"
     " a thirteen-bit item",
     "    writer.bits(sst, 8)                 # no alignment: the item is 13 bits",
     "    writer.octet(sst)",
     "ng-setup"),
    ("gnb-id-length-is-two-bits",
     "the gNB-ID length-of-length narrowed from four bits to two",
     "    writer.bits(gnb_id_bits - 22, 4)",
     "    writer.bits(gnb_id_bits - 22, 2)",
     "ng-setup-wide-id"),
]


def check(tool, NGAP, verbose=False):
    passed = 0
    failed = 0
    rows = []

    def verdict(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            rows.append(("%s\tAGREE" % name, ""))
        else:
            failed += 1
            rows.append(("%s\tMISMATCH\t%s" % (name, detail),
                         "MISMATCH %s %s" % (name, detail)))
        if verbose:
            print("%s\t%s\t%s" % (name, "AGREE" if ok else "MISMATCH", detail))

    for case in CASES:
        name = case["name"]
        try:
            got_hex = tool_run(tool, case["argv"])
        except RuntimeError as exc:
            verdict("%s-tool-runs" % name, False, str(exc))
            continue
        verdict("%s-tool-runs" % name, True)

        try:
            want = pycrate_encode(NGAP, *case["pycrate"]).hex()
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-encodes" % name, False, str(exc)[:160])
            continue
        verdict("%s-octets-agree" % name, got_hex == want,
                "tool %s pycrate %s" % (got_hex, want))

        try:
            procedure, read_rows = pycrate_decode_ie_values(
                NGAP, bytes.fromhex(got_hex), case)
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-reads" % name, False, str(exc)[:160])
            continue
        verdict("%s-pycrate-reads" % name, True)
        verdict("%s-procedure-code" % name, procedure == case["pycrate"][0],
                "read %r" % (procedure,))
        try:
            want_rows = pycrate_decode_ie_values(
                NGAP, pycrate_encode(NGAP, *case["pycrate"]), case)[1]
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-re-reads" % name, False, str(exc)[:160])
            continue
        verdict("%s-ie-values" % name, read_rows == want_rows,
                "read %r want %r" % (read_rows, want_rows))

    print("CASES\t%d" % (passed + failed))
    print("MISMATCHES\t%d" % failed)
    print("RESULT\t%s" % ("AGREE" if failed == 0 else "DISAGREE"))
    return failed


def negctl(NGAP, verbose=False):
    """Put each defect back into a scratch copy; the check must fail on it."""
    missed = []
    with open(TOOL) as handle:
        source = handle.read()
    for name, claim, old, new, case in NEGCTL:
        if old not in source:
            missed.append((name, "the text to break is not in the tool any more"))
            print("NEGCTL\t%s\tSTALE\t%s" % (name, claim))
            continue
        # The copy lives beside the real tool: it imports the shared PER
        # writer by directory, so a copy in a temp dir would fail to start and
        # look like a catch without testing the encoding at all.
        handle, victim = tempfile.mkstemp(
            prefix=".ngap_asn1_broken_", suffix=".py",
            dir=os.path.dirname(os.path.abspath(TOOL)))
        os.close(handle)
        try:
            with open(victim, "w") as broken:
                broken.write(source.replace(old, new, 1))
            spec = next(c for c in CASES if c["name"] == case)
            try:
                got_hex = tool_run(victim, spec["argv"])
                want = pycrate_encode(NGAP, *spec["pycrate"]).hex()
            except Exception as exc:             # noqa: BLE001
                missed.append((name, "%s (the copy could not run: %s)"
                               % (claim, str(exc)[:100])))
                print("NEGCTL\t%s\tUNRUNNABLE\t%s" % (name, claim))
                continue
            if got_hex != want:
                print("NEGCTL\t%s\tCAUGHT\t%s" % (name, claim))
            else:
                missed.append((name, claim))
                print("NEGCTL\t%s\tMISSED\t%s" % (name, claim))
        finally:
            os.unlink(victim)
    return missed


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--tool", default=TOOL)
    parser.add_argument("--negctl", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.tool):
        print("ERROR\t%s is missing" % args.tool)
        return 2
    try:
        NGAP = load_pycrate()
    except ImportError as exc:
        print("SKIP\tno pycrate NGAP decoder: %s" % exc)
        return 2

    failed = check(args.tool, NGAP, args.verbose)
    if args.negctl:
        missed = negctl(NGAP, args.verbose)
        print("NEGCTL\t%d put back, %d missed" % (len(NEGCTL), len(missed)))
        if missed:
            failed += len(missed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
