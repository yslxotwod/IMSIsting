#!/usr/bin/env python3
"""RANAP codec check against TS 25.413 and pycrate.

tools/ranap_asn1.py writes one RANAP message: the InitialUE-Message a rogue
Home NodeB sends to hand the core a subscriber's first NAS message.  It rides
inside a RUA DirectTransfer, so a wrong octet is not a formatting bug: it is
a subscriber attached to a network that will not page them, or a location
area the core files under a different cell.

The check is against the clause and against a second implementation, never
against the tool itself.

What the clause says (ETSI TS 25.413, with X.691 for the encoding):

  §9.1   RANAP-PDU is a CHOICE of initiatingMessage, successfulOutcome and
         unsuccessfulOutcome: APER opens it with a two-bit index, padded to
         octet 0x00.
  §9.1   InitiatingMessage is SEQUENCE { procedureCode, criticality, value
         open type } with no preamble.
  §9.3   Criticality is ENUMERATED { reject, ignore, notify, ... }: extension
         bit on top, index below, so reject is 0x00 and ignore is 0x40.
  §9.3   ProtocolIE-Container: preamble bit, alignment, then a SIXTEEN-bit
         count.  Each ProtocolIE-Field is a two-octet id, a criticality octet
         and an open type.
  §9.1.5 InitialUE-Message: CN-DomainIndicator (reject), LAI (ignore), SAI
         (ignore), NAS-PDU (ignore), all four mandatory.
  §9.2.1 CN-DomainIndicator is ENUMERATED { cs-domain(0), ps-domain(1) } and
         is NOT extensible: pycrate encodes ps-domain as ONE bit, 0x80 after
         the pad.  An extension bit in front moves ps-domain to 0x40, which
         reads back as cs-domain.
  §9.2.1 LAI and SAI are SEQUENCEs whose only preamble is the presence bit of
         the optional iE-Extensions, then aligned octets: LAI measures 48
         bits and SAI 64 in pycrate, which is 8 + 3*8 + 2*8 (+ 2*8 for SAI).
  §9.2.1 NAS-PDU is an OCTET STRING: determinant then octets, two-octet
         determinant above 127, so a 200-octet NAS is `80 c8` plus 200.

The procedure code is the one field that is silently unverified by every
encoder here: pycrate encodes an InitialUE-Message body under procedureCode 1
without complaint, and tshark dissects those same octets as an
Iu-ReleaseCommand.  The code comes from `tshark -G values` for
ranap.procedureCode, where id-InitialUE-Message is 19.

pycrate 0.8.1's pycrate_asn1dir.RANAP is the second implementation: given the
same values through its own structures it must produce the same octets, and
it must read the tool's octets back to those values.

Four defects put back into a scratch copy of the tool must each make this
check fail: the procedure code written as 1 (a well-formed Iu-Release), the
domain indicator given an extension bit, the LAI written without its optional
presence bit, and the NAS octet string written without its determinant.

usage: check_ranap_codec.py [--tool PATH] [--negctl] [--verbose]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(HERE, "ranap_asn1.py")
RUA = os.path.join(HERE, "rua_asn1.py")

LONG_NAS = bytes(range(200))
NAS = bytes.fromhex("0741010b0000")
PLMN = bytes.fromhex("00f110")

# The clause statement above, as values.  Transcribed from TS 25.413, not read
# from the tool: the point of the comparison is that the two were written
# apart.
CASES = [
    {
        "name": "ranap-initial-ue-ps",
        "argv": ["initial-ue", "--mcc", "001", "--mnc", "01", "--lac", "1",
                 "--sac", "2", "--nas", NAS.hex(), "--domain", "ps-domain"],
        "pycrate": (19, "reject", "InitialUE-Message", [
            (3, "reject", "CN-DomainIndicator", "ps-domain"),
            (15, "ignore", "LAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01"}),
            (58, "ignore", "SAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01",
                                   "sAC": b"\x00\x02"}),
            (16, "ignore", "NAS-PDU", NAS),
        ]),
        "expect": {"procedure-name": "id-InitialUE-Message",
                   "ie.0.domain": "ps-domain",
                   "ie.1.plmn": "00f110",
                   "ie.1.lac": "1",
                   "ie.2.sac": "2",
                   "ie.3.nas": NAS.hex()},
    },
    {
        # The domain bit is the whole difference between a packet connection
        # and a circuit-switched call the core bills differently.
        "name": "ranap-initial-ue-cs",
        "argv": ["initial-ue", "--mcc", "001", "--mnc", "01", "--lac", "1",
                 "--sac", "2", "--nas", NAS.hex(), "--domain", "cs-domain"],
        "pycrate": (19, "reject", "InitialUE-Message", [
            (3, "reject", "CN-DomainIndicator", "cs-domain"),
            (15, "ignore", "LAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01"}),
            (58, "ignore", "SAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01",
                                   "sAC": b"\x00\x02"}),
            (16, "ignore", "NAS-PDU", NAS),
        ]),
        "expect": {"procedure-name": "id-InitialUE-Message",
                   "ie.0.domain": "cs-domain"},
    },
    {
        # Past 127 octets the NAS determinant grows a second octet, in the
        # octet string and in the open type that carries it.  A writer whose
        # short cases are green gets this wrong.
        "name": "ranap-initial-ue-long",
        "argv": ["initial-ue", "--mcc", "001", "--mnc", "01", "--lac", "1",
                 "--sac", "2", "--nas", LONG_NAS.hex()],
        "pycrate": (19, "reject", "InitialUE-Message", [
            (3, "reject", "CN-DomainIndicator", "ps-domain"),
            (15, "ignore", "LAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01"}),
            (58, "ignore", "SAI", {"pLMNidentity": PLMN, "lAC": b"\x00\x01",
                                   "sAC": b"\x00\x02"}),
            (16, "ignore", "NAS-PDU", LONG_NAS),
        ]),
        "expect": {"procedure-name": "id-InitialUE-Message",
                   "ie.3.nas": LONG_NAS.hex()},
    },
]


def load_pycrate():
    from pycrate_asn1dir import RANAP
    return RANAP


def pycrate_encode(RANAP, procedure, criticality, typename, fields):
    pdu = RANAP.RANAP_PDU_Descriptions.RANAP_PDU
    ies = [{"id": ie_id, "criticality": crit, "value": (name, value)}
           for ie_id, crit, name, value in fields]
    pdu.set_val(("initiatingMessage", {
        "procedureCode": procedure,
        "criticality": criticality,
        "value": (typename, {"protocolIEs": ies}),
    }))
    return pdu.to_aper()


def tool_run(tool, argv):
    proc = subprocess.run([sys.executable, tool] + argv,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("tool failed: %s"
                           % (proc.stderr.strip() or proc.stdout.strip()))
    for line in proc.stdout.splitlines():
        if line.startswith("hex\t"):
            return line.split("\t", 1)[1]
    raise RuntimeError("tool printed no hex: %r" % proc.stdout)


def pycrate_read(RANAP, raw):
    pdu = RANAP.RANAP_PDU_Descriptions.RANAP_PDU
    pdu.from_aper(raw)
    kind, message = pdu.get_val()
    if kind != "initiatingMessage":
        raise RuntimeError("pycrate read %r, not an initiatingMessage" % (kind,))
    rows = [(field["id"], field["criticality"], field["value"][0],
             _plain(field["value"][1]))
            for field in message["value"][1]["protocolIEs"]]
    return message["procedureCode"], rows


def _plain(value):
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_plain(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


NEGCTL = [
    ("procedure-code-one",
     "the procedure code written as 1, which is a well-formed"
     " Iu-ReleaseCommand and not an initial UE message",
     TOOL,
     "    return _pdu(PROC_INITIAL_UE_MESSAGE, \"reject\", body)",
     "    return _pdu(1, \"reject\", body)",
     "ranap-initial-ue-ps"),
    ("domain-extension-bit",
     "the CN-DomainIndicator given an extension bit, which reads back as"
     " cs-domain",
     TOOL,
     "    writer = AperWriter()\n    writer.bit(CN_DOMAIN[domain])",
     "    writer = AperWriter()\n    writer.bit(0)\n    writer.bit(CN_DOMAIN[domain])",
     "ranap-initial-ue-ps"),
    ("lai-without-presence-bit",
     "the LAI written without its optional-extensions presence bit",
     TOOL,
     "    writer = AperWriter()\n    writer.bit(0)                       # no iE-Extensions\n    writer.align()",
     "    writer = AperWriter()\n    writer.align()",
     "ranap-initial-ue-ps"),
    ("nas-without-determinant",
     "the NAS octet string written without its length determinant",
     TOOL,
     "    writer = AperWriter()\n    _open_type(writer, nas)",
     "    writer = AperWriter()\n    writer.align()\n    writer.octets(nas)",
     "ranap-initial-ue-ps"),
]


def check(tool, RANAP, verbose=False):
    passed = 0
    failed = 0

    def verdict(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
        print("%s\t%s%s" % ("AGREE" if ok else "MISMATCH", name,
                            "" if ok or not detail else "\t" + detail))

    for case in CASES:
        name = case["name"]
        try:
            got_hex = tool_run(tool, case["argv"])
        except Exception as exc:                      # noqa: BLE001
            verdict("%s-tool-runs" % name, False, str(exc))
            continue
        verdict("%s-tool-runs" % name, True)

        procedure, criticality, typename, fields = case["pycrate"]
        try:
            want = pycrate_encode(RANAP, procedure, criticality, typename, fields)
        except Exception as exc:                      # noqa: BLE001
            verdict("%s-pycrate-encodes" % name, False, str(exc)[:160])
            continue
        verdict("%s-pycrate-encodes" % name, True)

        got = bytes.fromhex(got_hex)
        verdict("%s-octets-agree" % name, got == want,
                "tool %s want %s" % (got.hex(), want.hex()))

        try:
            read_procedure, read_rows = pycrate_read(RANAP, got)
        except Exception as exc:                      # noqa: BLE001
            verdict("%s-pycrate-reads" % name, False, str(exc)[:160])
            continue
        verdict("%s-pycrate-reads" % name, True)

        want_procedure, want_rows = pycrate_read(RANAP, want)
        verdict("%s-procedure-code" % name, read_procedure == procedure,
                "read %r want %r" % (read_procedure, procedure))
        verdict("%s-ie-values" % name, read_rows == want_rows,
                "read %r want %r" % (read_rows, want_rows))

        proc = subprocess.run([sys.executable, tool, "decode", got_hex],
                              capture_output=True, text=True)
        verdict("%s-tool-decodes" % name, proc.returncode == 0,
                proc.stderr.strip())
        if proc.returncode == 0:
            rows = dict(line.split("\t", 1) for line in proc.stdout.splitlines()
                        if "\t" in line)
            for key, value in case["expect"].items():
                verdict("%s-tool-%s" % (name, key), rows.get(key) == value,
                        "read %r want %r" % (rows.get(key), value))

    print("CASES\t%d" % passed)
    print("MISMATCHES\t%d" % failed)
    print("RESULT\t%s" % ("AGREE" if failed == 0 else "DISAGREE"))
    return 0 if failed == 0 else 1


def negctl(RANAP, verbose=False):
    """Put each defect back into a scratch copy and require the check to fail."""
    caught = 0
    for name, description, filename, old, new, case_name in NEGCTL:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = os.path.join(tmp, "tools")
            shutil.copytree(os.path.dirname(TOOL), scratch,
                            ignore=shutil.ignore_patterns("__pycache__"))
            target = os.path.join(scratch, os.path.basename(filename))
            with open(target) as handle:
                text = handle.read()
            if old not in text:
                print("BROKEN\t%s\tcannot find the text to break" % name)
                continue
            with open(target, "w") as handle:
                handle.write(text.replace(old, new, 1))
            case = next(c for c in CASES if c["name"] == case_name)
            scratch_tool = os.path.join(scratch, os.path.basename(TOOL))
            try:
                got_hex = tool_run(scratch_tool, case["argv"])
            except Exception as exc:                  # noqa: BLE001
                print("CAUGHT\t%s\t%s\t%s" % (name, description, str(exc)[:120]))
                caught += 1
                continue
            procedure, criticality, typename, fields = case["pycrate"]
            want = pycrate_encode(RANAP, procedure, criticality, typename, fields)
            if bytes.fromhex(got_hex) == want:
                print("MISSED\t%s\t%s" % (name, description))
            else:
                print("CAUGHT\t%s\t%s\t%s" % (name, description,
                                              "octets differ from the clause"))
                caught += 1
    print("NEGCTL\t%d/%d" % (caught, len(NEGCTL)))
    print("RESULT\t%s" % ("CAUGHT" if caught == len(NEGCTL) else "MISSED"))
    return 0 if caught == len(NEGCTL) else 1


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tool", default=TOOL)
    parser.add_argument("--negctl", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    RANAP = load_pycrate()
    if args.negctl:
        return negctl(RANAP, args.verbose)
    return check(args.tool, RANAP, args.verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
