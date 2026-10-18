#!/usr/bin/env python3
"""X2AP codec check against TS 36.423 and pycrate.

tools/x2ap_asn1.py writes X2AP octets. X2AP is what two base stations say to
each other, and it is the protocol a fake cell answers an honest one with, so
a wrong IE number is a claim about which network and which cell made in the
wrong field, and a wrong bit layout is a message that dissects without an
error and means something else. So the tool is checked against the clause
statement and against a second implementation, not against itself.

What the clause says (ETSI TS 136 423 V16.0.0, with X.691 for the encoding):

  §9.1   X2AP-PDU is a CHOICE of initiatingMessage, successfulOutcome and
         unsuccessfulOutcome -- extensible, so APER opens it with the
         extension bit then a two-bit choice index, both zero: octet 0x00.
  §9.1   InitiatingMessage is SEQUENCE { procedureCode INTEGER (0..255),
         criticality, value open type }. No preamble: no extension marker and
         no OPTIONAL on it.
  §9.3   Criticality is ENUMERATED { reject, ignore, notify, ... }: the
         extension bit is the top bit and the index sits in the two below it,
         so reject is 0x00 and not 0x01.
  §9.3   ProtocolIE-Container is SEQUENCE (SIZE(0..65535)) OF
         ProtocolIE-Field and IS extensible: preamble bit, alignment, then a
         SIXTEEN-bit count.
  §9.3   ProtocolIE-Field is { id INTEGER(0..65535), criticality, value open
         type }: id in two octets, criticality octet, length determinant.
  §9.2   The IE ids used below: ServedCells 20, GlobalENB-ID 21.
  X.691 §14  A SEQUENCE (SIZE(1..256)) OF has a count of (n-1) in EIGHT bits.
  X.691 §15  ServedCells-Item is { servedCellInfo, neighbour-Information
         OPTIONAL, iE-Extensions OPTIONAL } and ServedCell-Information is
         extensible with its own optional iE-Extensions: the preamble is the
         extension bit plus the presence bits, ONE run of three bits for the
         item and two for the cell, not an octet each.
  X.691 §13.2  pCI is INTEGER (0..503) and in aligned PER an integer under
         65536 is written in two octets with no length prefix.
  X.691 §16  ECGI is { pLMN-Identity OCTET STRING(SIZE(3)), eUTRANcellIdentifier
         BIT STRING(SIZE(28)), iE-Extensions OPTIONAL }: the SEQUENCE has a
         preamble and an alignment before the PLMN, and after that the 28-bit
         cell id runs on WITHOUT padding. The TAC of ServedCell-Information
         follows it in the same bit run and lands across octets. This is the
         layout a writer gets wrong by aligning after the cell id, and both
         referees catch it.
  X.691 §14  broadcastPLMNs is SEQUENCE (SIZE(1..6)) OF PLMN-Identity: count
         of (n-1) in THREE bits, then the run is padded and each PLMN is three
         octets.
  X.691 §14  EUTRA-Mode-Info is an extensible CHOICE over fDD and tDD:
         extension bit, a ONE-bit index, then the chosen SEQUENCE's extension
         bit and its iE-Extensions presence bit, then an alignment.
  §9.2.2  EUTRA-FDD-Info is { uL-EARFCN, dL-EARFCN, uL-Transmission-Bandwidth,
         dL-Transmission-Bandwidth, iE-Extensions OPTIONAL }: the EARFCNs are
         sixteen bits each, and the two bandwidths are extensible ENUMERATED
         in four bits each -- bw6 is 0000 and bw100 is 0101.

pycrate 0.8.1's pycrate_asn1dir.X2AP is the second implementation: given the
same values through its own structure it must produce the same octets, and it
must read the tool's octets back to those values.

Four defects put back into a scratch copy of the tool must each make this
check fail: the cell id padded before the TAC (the finding above), the item
preamble given its own octet, the PLMN count widened to eight bits, and the
bandwidth nibble widened to five bits.

One defect that is NOT in that list, and why: writing the item preamble one
bit short. The item and the cell preamble are all zero bits followed by an
alignment, so dropping a zero there changes the padding and not the octets --
which means a length error in an all-zero preamble is invisible on the wire
until something sets one of those bits. The control that does catch a
preamble-length error is the one that spends an octet on it, and that is what
the second entry below breaks.

usage: check_x2ap_codec.py [--tool PATH] [--negctl] [--verbose]
"""
import argparse
import os
import subprocess
import sys
import tempfile

TOOL = "/home/ysl/IMSIsting/tools/x2ap_asn1.py"

CELL_A = {
    "pCI": 301,
    "cellId": {"pLMN-Identity": b"\x00\xf1\x10",
               "eUTRANcellIdentifier": (0x0A1C010, 28)},
    "tAC": b"\x00\x01",
    "broadcastPLMNs": [b"\x00\xf1\x10"],
    "eUTRA-Mode-Info": ("fDD", {
        "uL-EARFCN": 24300, "dL-EARFCN": 6300,
        "uL-Transmission-Bandwidth": "bw100",
        "dL-Transmission-Bandwidth": "bw100"}),
}

CELL_B = {
    "pCI": 400,
    "cellId": {"pLMN-Identity": b"\x13\x00\x62",
               "eUTRANcellIdentifier": (0x0FFFFFF, 28)},
    "tAC": b"\xbe\xef",
    "broadcastPLMNs": [b"\x13\x00\x62"],
    "eUTRA-Mode-Info": ("fDD", {
        "uL-EARFCN": 18300, "dL-EARFCN": 1825,
        "uL-Transmission-Bandwidth": "bw25",
        "dL-Transmission-Bandwidth": "bw50"}),
}

# The clause statement above, as values. Transcribed from TS 36.423, not read
# from the tool: the point of the comparison is that the two were written
# apart.
CASES = [
    {
        "name": "x2setup-001-01",
        "argv": ["x2setup", "--mcc", "1", "--mnc", "01", "--enb-id", "0xA1C01",
                 "--pci", "301", "--cell-id", "0x0A1C010", "--tac", "1"],
        "pycrate": (6, "reject", "X2SetupRequest", [
            (21, "reject", "GlobalENB-ID",
             {"pLMN-Identity": b"\x00\xf1\x10",
              "eNB-ID": ("macro-eNB-ID", (0xA1C01, 20))}),
            (20, "reject", "ServedCells", [{"servedCellInfo": CELL_A}]),
        ]),
    },
    {
        # Every field at a different width: a three-digit MNC, the cell id at
        # its 28-bit maximum, and a tAC whose high octet is non-zero, so an
        # alignment after the cell id cannot hide inside a zero.
        "name": "x2setup-310-260",
        "argv": ["x2setup", "--mcc", "310", "--mnc", "260",
                 "--enb-id", "0x12345", "--pci", "400",
                 "--cell-id", "0x0FFFFFF", "--tac", "0xBEEF",
                 "--ul-earfcn", "18300", "--dl-earfcn", "1825",
                 "--ul-bw", "bw25", "--dl-bw", "bw50"],
        "pycrate": (6, "reject", "X2SetupRequest", [
            (21, "reject", "GlobalENB-ID",
             {"pLMN-Identity": b"\x13\x00\x62",
              "eNB-ID": ("macro-eNB-ID", (0x12345, 20))}),
            (20, "reject", "ServedCells", [{"servedCellInfo": CELL_B}]),
        ]),
    },
]


def load_pycrate():
    from pycrate_asn1dir import X2AP
    return X2AP


def pycrate_encode(X2AP, procedure, criticality, typename, fields):
    """Set the PDU inside pycrate's own structures and encode aligned PER."""
    pdu = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
    ies = [{"id": ie_id, "criticality": crit, "value": (name, value)}
           for ie_id, crit, name, value in fields]
    pdu.set_val(("initiatingMessage", {
        "procedureCode": procedure,
        "criticality": criticality,
        "value": (typename, {"protocolIEs": ies}),
    }))
    return pdu.to_aper()


def tool_run(tool, argv):
    """Ask the tool for one message; return its hex text."""
    proc = subprocess.run([sys.executable, tool] + argv,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("tool failed: %s"
                           % (proc.stderr.strip() or proc.stdout.strip()))
    for line in proc.stdout.splitlines():
        if line.startswith("hex\t"):
            return line.split("\t", 1)[1]
    raise RuntimeError("tool printed no hex: %r" % proc.stdout)


def pycrate_read(X2AP, raw):
    pdu = X2AP.X2AP_PDU_Descriptions.X2AP_PDU
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
    ("cell-id-padded-before-tac",
     "an alignment inserted between the 28-bit cell id and the TAC",
     '        writer.bits(cell["tac"] & 0xFFFF, 16)   # no realignment: see docstring',
     '        writer.align()\n        writer.bits(cell["tac"] & 0xFFFF, 16)',
     "x2setup-001-01"),
    ("item-preamble-own-octet",
     "the ServedCells-Item preamble aligned on its own octet, so the two"
     " preambles stop sharing one run",
     "        writer.bit(0)                   # no iE-Extensions\n"
     "        writer.bit(0)                   # ServedCell-Information: no extensions",
     "        writer.bit(0)                   # no iE-Extensions\n"
     "        writer.align()\n"
     "        writer.bit(0)                   # ServedCell-Information: no extensions",
     "x2setup-001-01"),
    ("plmn-count-eight-bits",
     "the broadcastPLMNs count widened from three bits to eight",
     '        writer.bits((len(plmns) if plmns else 1) - 1, 3)',
     '        writer.bits((len(plmns) if plmns else 1) - 1, 8)',
     "x2setup-001-01"),
    ("bandwidth-five-bits",
     "the transmission bandwidth nibble widened to five bits",
     '        writer.bits(BW[cell.get("dl_bw", "bw100")], 4)',
     '        writer.bits(BW[cell.get("dl_bw", "bw100")], 5)',
     "x2setup-310-260"),
]


def check(tool, X2AP, verbose=False):
    passed = 0
    failed = 0

    def verdict(name, ok, detail=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            if verbose:
                print("%s\tAGREE" % name)
        else:
            failed += 1
            print("MISMATCH %s %s" % (name, detail))

    for case in CASES:
        name = case["name"]
        try:
            got_hex = tool_run(tool, case["argv"])
        except RuntimeError as exc:
            verdict("%s-tool-runs" % name, False, str(exc))
            continue
        verdict("%s-tool-runs" % name, True)

        try:
            want = pycrate_encode(X2AP, *case["pycrate"])
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-encodes" % name, False, str(exc)[:160])
            continue
        verdict("%s-octets-agree" % name, got_hex == want.hex(),
                "tool %s pycrate %s" % (got_hex, want.hex()))

        try:
            procedure, read_rows = pycrate_read(X2AP, bytes.fromhex(got_hex))
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-reads" % name, False, str(exc)[:160])
            continue
        verdict("%s-pycrate-reads" % name, True)
        verdict("%s-procedure-code" % name, procedure == case["pycrate"][0],
                "read %r" % (procedure,))
        verdict("%s-ie-values" % name, read_rows == pycrate_read(X2AP, want)[1],
                "read %r" % (read_rows,))

        # The tool's own decoder must read its own octets back: the message
        # is only useful to this tree if the reader and the writer agree on
        # where the TAC is.
        proc = subprocess.run([sys.executable, tool, "decode", got_hex],
                              capture_output=True, text=True)
        verdict("%s-tool-decodes" % name, proc.returncode == 0,
                proc.stderr.strip()[:160])
        if proc.returncode == 0:
            text = proc.stdout
            cell = [ln for ln in text.splitlines()
                    if ln.startswith("ie\tServedCells")][0]
            tac = case["pycrate"][3][1][3][0]["servedCellInfo"]["tAC"]
            verdict("%s-tool-reads-the-tac" % name,
                    "tac %d" % int.from_bytes(tac, "big") in cell, cell)

    print("CASES\t%d" % (passed + failed))
    print("MISMATCHES\t%d" % failed)
    print("RESULT\t%s" % ("AGREE" if failed == 0 else "DISAGREE"))
    return failed


def negctl(X2AP, verbose=False):
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
            prefix=".x2ap_asn1_broken_", suffix=".py",
            dir=os.path.dirname(os.path.abspath(TOOL)))
        os.close(handle)
        try:
            with open(victim, "w") as broken:
                broken.write(source.replace(old, new, 1))
            spec = next(c for c in CASES if c["name"] == case)
            try:
                got_hex = tool_run(victim, spec["argv"])
                want = pycrate_encode(X2AP, *spec["pycrate"]).hex()
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
        X2AP = load_pycrate()
    except ImportError as exc:
        print("SKIP\tno pycrate X2AP decoder: %s" % exc)
        return 2

    failed = check(args.tool, X2AP, args.verbose)
    if args.negctl:
        missed = negctl(X2AP, args.verbose)
        print("NEGCTL\t%d put back, %d missed" % (len(NEGCTL), len(missed)))
        if missed:
            failed += len(missed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
