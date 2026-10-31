#!/usr/bin/env python3
"""Referee for tools/ngap_handover.py -- the N2 handover chain encoder.

What is checked, and why it needs a second implementation:

  * The octets of HandoverRequired, HandoverCommand and HandoverNotify are
    encoded again from the same values by pycrate 0.8.1's
    pycrate_asn1dir.NGAP, which is compiled from the ASN.1 of TS 38.413
    clause 9.3 rather than from anybody's summary of it.  The two encodings
    must be identical octet for octet.  An encoder can be wrong and still
    produce something a dissector will parse -- it then means a different
    cell, a different PLMN or a different session -- so "tshark decoded it"
    is not the assertion; "two independent encoders agree" is.
  * pycrate reads the tool's octets back and must return the same values, so
    a case cannot pass by both sides being equally wrong about a value the
    tool never wrote.
  * tshark 4.2.2's NGAP dissector must name the three messages, their
    procedure codes and their IEs.  The frames are built here by hand:
    text2pcap cannot frame a bare PDU, so this file writes the SCTP common
    header, one DATA chunk and the IP wrapper itself.
  * Four defects put back into a scratch copy of the tool (a GlobalRANNodeID
    index one bit too wide, a SEQUENCE OF count that forgot its lower bound,
    HandoverNotify given PathSwitchRequest's procedure code, and the
    UserLocationInformation criticality left at reject) must each make the
    check fail.  A referee that cannot fail proves nothing.

Exit 0 the encoders agree, 1 a disagreement, 2 the check could not run.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOL = os.path.join(ROOT, "tools", "ngap_handover.py")
TSHARK = shutil.which("tshark") or "/usr/bin/tshark"

# TS 38.413 clause 9.1.4.2 / 9.1.4.3 and clause 9.2.3, stated once here so a
# case can be read without the tool open: the three messages, their procedure
# codes, their PDU choice and the criticality of the procedure.
PROCEDURES = {
    "HandoverRequired": (12, "initiatingMessage", "reject"),
    "HandoverCommand": (12, "successfulOutcome", "reject"),
    "HandoverNotify": (11, "initiatingMessage", "ignore"),
}

PLMN = bytes.fromhex("00f110")                       # MCC 001, MNC 01
PLMN_US = bytes.fromhex("130062")                    # MCC 310, MNC 260


def verdict(name, ok, detail=""):
    sys.stdout.write("ASSERTION\t%s\t%s%s\n"
                     % (name, "PASS" if ok else "FAIL",
                        "" if not detail else "\t" + detail))
    return ok


def tool_run(argv, tool=TOOL):
    """Run the encoder and return (process, hex or None)."""
    proc = subprocess.run([sys.executable, tool] + list(argv),
                          capture_output=True, text=True)
    hexed = None
    for line in proc.stdout.splitlines():
        if line.startswith("hex\t"):
            hexed = line.split("\t", 1)[1]
    return proc, hexed


# ---------------------------------------------------------------------------
# The values.  One builder per message; the tool is given the same numbers on
# its command line, so a disagreement is about encoding, never about inputs.
# ---------------------------------------------------------------------------

def target_id_value(gnb=0xA1C01, gnb_bits=22, plmn=PLMN, tac="000001"):
    """TargetID (§9.3.1.46) as targetRANNodeID { globalGNB-ID, TAI }."""
    return ("targetRANNodeID", {
        "globalRANNodeID": ("globalGNB-ID", {
            "pLMNIdentity": plmn,
            "gNB-ID": ("gNB-ID", (gnb, gnb_bits))}),
        "selectedTAI": {"pLMNIdentity": plmn, "tAC": bytes.fromhex(tac)}})


def sessions_value(items):
    """PDUSessionResourceListHORqd (§9.3.1.55)."""
    return [{"pDUSessionID": pdu_id,
             "handoverRequiredTransfer": transfer}
            for pdu_id, transfer in items]


def required_value(amf=1, ran=2, ho_type="intra5gs", cause="unspecified",
                   target=None, sessions=((5, b"\x01\x02"),),
                   container=b"\x03\x04\x05"):
    return ("HandoverRequired", {"protocolIEs": [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran)},
        {"id": 29, "criticality": "reject", "value": ("HandoverType", ho_type)},
        {"id": 15, "criticality": "ignore", "value": ("Cause", ("radioNetwork", cause))},
        {"id": 105, "criticality": "reject",
         "value": ("TargetID", target or target_id_value())},
        {"id": 61, "criticality": "reject",
         "value": ("PDUSessionResourceListHORqd", sessions_value(sessions))},
        {"id": 101, "criticality": "reject",
         "value": ("SourceToTarget-TransparentContainer", container)},
    ]})


def command_value(amf=1, ran=2, ho_type="intra5gs", nas=b"\x01\x02\x03",
                  container=b"\x0a\x0b"):
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran)},
        {"id": 29, "criticality": "reject", "value": ("HandoverType", ho_type)},
    ]
    if nas:
        ies.append({"id": 39, "criticality": "reject",
                    "value": ("NASSecurityParametersFromNGRAN", nas)})
    ies.append({"id": 106, "criticality": "reject",
                "value": ("TargetToSource-TransparentContainer", container)})
    return ("HandoverCommand", {"protocolIEs": ies})


def notify_value(amf=7, ran=9, plmn=PLMN, nci=0x5A1C01, tac="000001"):
    """HandoverNotify: AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, UserLocationInformation.

    Its container (HandoverNotifyIEs, §9.2.3.5) holds no session list, and the
    location IE is CRITICALITY ignore here where other messages give it
    reject -- both are stated in the clause, not chosen here.
    """
    return ("HandoverNotify", {"protocolIEs": [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran)},
        {"id": 121, "criticality": "ignore",
         "value": ("UserLocationInformation", ("userLocationInformationNR", {
             "nR-CGI": {"pLMNIdentity": plmn, "nRCellIdentity": (nci, 36)},
             "tAI": {"pLMNIdentity": plmn, "tAC": bytes.fromhex(tac)}}))},
    ]})


CASES = [
    {
        "name": "handover-required",
        "argv": ["required", "--amf-ue-id", "1", "--ran-ue-id", "2",
                 "--plmn", "001/01", "--gnb-id", "0xA1C01", "--tac", "000001",
                 "--cause", "unspecified", "--pdu-session", "5:0102",
                 "--source-to-target", "030405"],
        "value": required_value(),
    },
    {
        "name": "handover-command",
        "argv": ["command", "--amf-ue-id", "1", "--ran-ue-id", "2",
                 "--plmn", "001/01", "--gnb-id", "0xA1C01", "--tac", "000001",
                 "--nas-security", "010203", "--target-to-source", "0a0b"],
        "value": command_value(),
    },
    {
        "name": "handover-notify",
        "argv": ["notify", "--amf-ue-id", "7", "--ran-ue-id", "9",
                 "--plmn", "001/01", "--nci", "0x5A1C01", "--tac", "000001"],
        "value": notify_value(),
    },
    {
        # A 32-bit gNB identity and three sessions: the width field moves the
        # identity's length and the alignment with it, and a count over one
        # session is where a SEQUENCE OF that ignores its lower bound breaks.
        "name": "required-32bit-three-sessions",
        "argv": ["required", "--amf-ue-id", "4294967295",
                 "--ran-ue-id", "4294967295", "--plmn", "310/260",
                 "--gnb-id", "0xDEADBEEF", "--gnb-id-bits", "32",
                 "--tac", "ffffff", "--cause", "unspecified",
                 "--pdu-session", "1:aa", "--pdu-session", "2:bb",
                 "--pdu-session", "255:ccdd", "--source-to-target", "00"],
        "value": required_value(
            amf=4294967295, ran=4294967295,
            target=target_id_value(gnb=0xDEADBEEF, gnb_bits=32,
                                   plmn=PLMN_US, tac="ffffff"),
            sessions=((1, b"\xaa"), (2, b"\xbb"), (255, b"\xcc\xdd")),
            container=b"\x00"),
    },
    {
        "name": "required-fivegs-to-eps",
        "argv": ["required", "--amf-ue-id", "3", "--ran-ue-id", "4",
                 "--plmn", "001/01", "--gnb-id", "0xA1C01", "--tac", "000001",
                 "--handover-type", "fivegs-to-eps",
                 "--cause", "handover-desirable-for-radio-reason",
                 "--pdu-session", "5:0102", "--source-to-target", "030405"],
        "value": required_value(
            amf=3, ran=4, ho_type="fivegs-to-eps",
            cause="handover-desirable-for-radio-reason"),
    },
]

# A refusal is a result too: the tool must say which clause stopped it.
REFUSALS = [
    ("notify-refuses-session-list",
     ["notify", "--pdu-session", "5:0102"],
     "HandoverNotify carries no PDUSessionResourceListHORqd"),
    ("unknown-message-is-a-usage-error",
     ["handover-request"], "unknown message"),
    ("tac-must-be-three-octets",
     ["required", "--tac", "0001"], "three octets"),
    ("gnb-id-width-is-22-to-32-bits",
     ["required", "--gnb-id-bits", "16"], "22 to 32"),
    ("gnb-id-must-fit-its-width",
     ["required", "--gnb-id", "0xFFFFFF", "--gnb-id-bits", "22"], "out of range"),
]

NEGCTL = [
    ("global-ran-node-id-index",
     "GlobalRANNodeID's index widened to three bits",
     "    writer.bits(0, 2)                                   # globalGNB-ID",
     "    writer.bits(0, 3)                                   # globalGNB-ID",
     "handover-required"),
    ("sequence-of-count",
     "the SEQUENCE OF count written without its lower bound",
     "    writer.bits(len(items) - 1, 8)",
     "    writer.bits(len(items), 8)",
     "required-32bit-three-sessions"),
    ("notify-procedure-code",
     "HandoverNotify given PathSwitchRequest's procedure code",
     "PROCEDURE_HANDOVER_NOTIFICATION = 11",
     "PROCEDURE_HANDOVER_NOTIFICATION = 25",
     "handover-notify"),
    ("location-criticality",
     "UserLocationInformation left at reject in HandoverNotify",
     '    return field[:2] + bytes([_criticality_octet("ignore")]) + field[3:]',
     "    return field",
     "handover-notify"),
]


# ---------------------------------------------------------------------------
# tshark.  The frames are assembled here because text2pcap cannot frame a
# bare PDU: an SCTP common header, one DATA chunk carrying the NGAP PDU, the
# IP wrapper and a pcap header.
# ---------------------------------------------------------------------------

def sctp_datagram(payload):
    chunk = (struct.pack("!BBH", 0, 0x03, 16 + len(payload))
             + struct.pack("!IHHI", 1, 0, 0, 60) + payload)
    return struct.pack("!HHII", 38412, 38412, 0, 0) + chunk


def ipv4_datagram(payload):
    def addr(text):
        return bytes(int(part) for part in text.split("."))
    return (struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                        64, 132, 0, addr("10.0.0.1"), addr("10.0.0.2"))
            + payload)


def write_pcap(path, payloads):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
        for index, payload in enumerate(payloads):
            frame = ipv4_datagram(sctp_datagram(payload))
            handle.write(struct.pack("<IIII", 1600000000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


def tshark_leg(hexes, verbose=False):
    """Ask tshark to name the messages out of a hand-built capture.

    The fourth frame is the 32-bit gNB identity with three sessions: pycrate
    0.8.1 cannot decode the octets its own encoder writes for it, so the
    dissector is the only referee that reads that case back, and it must.
    """
    failed = 0
    if not os.path.exists(TSHARK):
        verdict("tshark-available", False, "no tshark at %s" % (TSHARK,))
        return 1
    work = tempfile.mkdtemp(prefix="ngap-handover-")
    try:
        path = os.path.join(work, "chain.pcap")
        order = ["handover-required", "handover-command", "handover-notify",
                 "required-32bit-three-sessions"]
        write_pcap(path, [bytes.fromhex(hexes[name]) for name in order])
        proc = subprocess.run(
            [TSHARK, "-r", path, "-d", "sctp.port==38412,ngap", "-T", "fields",
             "-e", "ngap.NGAP_PDU", "-e", "ngap.procedureCode",
             "-e", "ngap.HandoverType", "-e", "ngap.TargetID",
             "-e", "ngap.UserLocationInformation", "-e", "ngap.gNB_ID",
             "-e", "ngap.PDUSessionResourceListHORqd", "-e", "ngap.tAC"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            verdict("tshark-reads-capture", False, proc.stderr.strip()[:200])
            return 1
        rows = [line.split("\t") for line in proc.stdout.splitlines()]
        # PDU choice and procedure code, per frame: initiatingMessage/
        # successfulOutcome and the clause's code, never this file's opinion.
        want = [("0", "12"), ("1", "12"), ("0", "11"), ("0", "12")]
        for index, expected in enumerate(want):
            row = rows[index] if index < len(rows) else []
            got = tuple(row[:2]) if len(row) >= 2 else ()
            failed += not verdict("tshark-frame%d-pdu" % (index + 1,),
                                  got == expected, "read %r want %r" % (got, expected))
        # The IEs each message must carry, as the dissector reports them.
        failed += not verdict(
            "tshark-required-ies",
            len(rows) > 0 and rows[0][2:4] == ["0", "0"],
            "HandoverType/TargetID %r" % (rows[0][2:4] if rows else [],))
        failed += not verdict(
            "tshark-notify-location",
            len(rows) > 2 and rows[2][4] == "1",
            "UserLocationInformation %r" % (rows[2][4:5] if len(rows) > 2 else [],))
        # The 32-bit identity and the three-session count, as the dissector
        # prints them: the value the encoder was given, not merely "decode ok".
        failed += not verdict(
            "tshark-32bit-gnb-id",
            len(rows) > 3 and rows[3][5].lower() == "deadbeef"
            and rows[3][6] == "3"
            and rows[3][7].lower() in ("ffffff", "16777215"),
            "gNB-ID/sessions/TAC %r" % (rows[3][5:8] if len(rows) > 3 else [],))
        if verbose:
            sys.stdout.write(proc.stdout)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return failed


def negctl(verbose=False):
    """Put each defect back into a scratch copy; the check must catch it."""
    missed = 0
    with open(TOOL) as handle:
        source = handle.read()
    for name, claim, old, new, case in NEGCTL:
        if old not in source:
            missed += not verdict("negctl-%s" % (name,), False,
                                  "STALE: the text to break is gone")
            continue
        # The copy must live beside the real tool: it imports the shared PER
        # writer by directory, so a copy in a temp tree would fail to start
        # and look like a catch without testing the encoding at all.
        handle_, victim = tempfile.mkstemp(
            prefix=".ngap_handover_broken_", suffix=".py",
            dir=os.path.dirname(os.path.abspath(TOOL)))
        os.close(handle_)
        try:
            with open(victim, "w") as broken:
                broken.write(source.replace(old, new, 1))
            spec = next(item for item in CASES if item["name"] == case)
            proc, hexed = tool_run(spec["argv"], tool=victim)
            from pycrate_asn1dir import NGAP       # noqa: F401  (see verdict)
            pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            pdu.set_val(pycrate_value(spec))
            want = pdu.to_aper().hex()
            caught = hexed != want
            if verbose:
                sys.stdout.write("negctl %s: %s\n" % (name, hexed))
            missed += not verdict("negctl-%s" % (name,), caught,
                                  "CAUGHT (%s)" % (claim,) if caught
                                  else "MISSED (%s)" % (claim,))
        finally:
            os.unlink(victim)
    return missed


def pycrate_value(spec):
    message, body = spec["value"]
    procedure, choice, criticality = PROCEDURES[message]
    return (choice, {"procedureCode": procedure, "criticality": criticality,
                     "value": (message, body)})


def ie_signature(spec):
    """The (id, criticality) pairs a message was written with, in order."""
    return [(ie["id"], ie["criticality"])
            for ie in spec["value"][1]["protocolIEs"]]


def referee_self_consistent(pdu, spec, NGAP):
    """Can pycrate decode the octets pycrate itself writes for this case?"""
    pdu.set_val(pycrate_value(spec))
    enc = pdu.to_aper()
    try:
        pdu.from_aper(enc)
        again = pdu.to_aper()
    except Exception as exc:                        # noqa: BLE001
        return False, str(exc)[:80]
    if again == enc:
        return True, ""
    try:
        read = pdu.get_val()
        got = [(ie["id"], ie["criticality"])
               for ie in read[1]["value"][1]["protocolIEs"]]
        return False, "read back %r" % (got,)
    except Exception:                               # noqa: BLE001
        return False, "re-encoded %d octets, wrote %d" % (len(again), len(enc))


def main(argv):
    verbose = "--verbose" in argv
    try:
        from pycrate_asn1dir import NGAP
    except Exception as exc:                        # noqa: BLE001
        sys.stderr.write("UNRUNNABLE\tno pycrate for %s: %s\n"
                         % (sys.executable, exc))
        return 2
    if not os.path.exists(TOOL):
        sys.stderr.write("UNRUNNABLE\t%s is missing\n" % (TOOL,))
        return 2

    failed = 0
    hexes = {}
    pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    for spec in CASES:
        proc, hexed = tool_run(spec["argv"])
        name = spec["name"]
        if proc.returncode != 0 or not hexed:
            failed += not verdict(name, False,
                                  "encoder exit %d: %s"
                                  % (proc.returncode, proc.stderr.strip()[:120]))
            continue
        hexes[name] = hexed
        pdu.set_val(pycrate_value(spec))
        want = pdu.to_aper().hex()
        failed += not verdict(name, hexed == want,
                              "%d octets" % (len(hexed) // 2,)
                              if hexed == want else
                              "mine %s want %s" % (hexed, want))
        # pycrate reads the tool's own octets back to the same IE list, so a
        # case cannot pass by both encoders agreeing on a value nobody wrote.
        # pycrate 0.8.1's NGAP decoder is asymmetric for three of these
        # structures -- it cannot decode its own octets for a session-list
        # item, for a 32-bit gNB identity, or for an IE that follows one. That
        # is a limit of the referee, so the case is reported SKIP with the
        # reason, and only when the reference bytes fail the same way;
        # otherwise a real defect would be excused as an oracle limitation.
        consistent, why = referee_self_consistent(pdu, spec, NGAP)
        if consistent:
            try:
                pdu.from_aper(bytes.fromhex(hexed))
                read = pdu.get_val()
                got = [(ie["id"], ie["criticality"])
                       for ie in read[1]["value"][1]["protocolIEs"]]
                failed += not verdict(
                    name + "-reads-back",
                    read[0] == PROCEDURES[spec["value"][0]][1]
                    and read[1]["procedureCode"] == PROCEDURES[spec["value"][0]][0]
                    and got == ie_signature(spec),
                    "pycrate read %r %r %r" % (read[0],
                                               read[1]["procedureCode"], got))
            except Exception as exc:                # noqa: BLE001
                failed += not verdict(name + "-reads-back", False, str(exc)[:160])
        else:
            sys.stdout.write("ASSERTION\t%s\tSKIP\tpycrate's decoder cannot "
                             "reproduce its own octets here (%s)\n"
                             % (name + "-reads-back", why))

    for name, argv_, needle in REFUSALS:
        proc, _ = tool_run(argv_)
        said = (proc.stdout + proc.stderr)
        failed += not verdict(name, proc.returncode == 2 and needle in said,
                              "exit %d, said %r" % (proc.returncode,
                                                    said.strip()[:100]))

    if len(hexes) == len(CASES):
        failed += tshark_leg(hexes, verbose)

    if "--negctl" in argv:
        failed += negctl(verbose)

    sys.stdout.write("CASES\t%d\n" % (len(CASES) + len(REFUSALS),))
    sys.stdout.write("MISMATCHES\t%d\n" % (failed,))
    sys.stdout.write("RESULT\t%s\n" % ("AGREE" if failed == 0 else "DISAGREE",))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
