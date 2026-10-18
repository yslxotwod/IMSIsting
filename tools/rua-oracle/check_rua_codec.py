#!/usr/bin/env python3
"""RUA codec check against TS 25.468 and pycrate.

tools/rua_asn1.py writes RUA octets.  RUA is how a Home NodeB opens a
signalling connection to the core and hands it a RANAP message, so an octet
of difference is not a formatting bug: it is a connection that opens with the
wrong context, or a call the core files as an emergency call, or a RANAP that
the core reads one byte shifted.  The tool is therefore checked against the
clause and against a second implementation, never against itself.

What the clause says (ETSI TS 25.468, with X.691 for the encoding):

  §9.1   RUA-PDU is a CHOICE of initiatingMessage, successfulOutcome and
         unsuccessfulOutcome, extensible, so APER opens it with the extension
         bit and a two-bit index, both zero: octet 0x00.
  §9.1   InitiatingMessage is SEQUENCE { procedureCode, criticality, value
         open type } with no preamble.
  §9.3   Criticality is ENUMERATED { reject, ignore, notify, ... }: extension
         bit on top, index below, so reject is 0x00 and ignore is 0x40.
  §9.3   ProtocolIE-Container is SEQUENCE (SIZE(0..maxProtocolIEs)) OF
         ProtocolIE-Field, extensible: preamble bit, alignment, then a
         SIXTEEN-bit count.
  §9.3   ProtocolIE-Field is { id INTEGER(0..65535), criticality, value open
         type }: two-octet id, criticality octet, length determinant.
  §9.2   The procedure codes: Connect 1, DirectTransfer 2, Disconnect 3.
  §9.2   The IE ids used below: Context-ID 3, RANAP-Message 4,
         Establishment-Cause 6.
  §9.2.1 Context-ID is a BIT STRING (SIZE (24)): three octets, no padding
         question because 24 bits is whole octets.
  §9.2.1 Establishment-Cause is ENUMERATED { emergency-call(0), normal-call(1) }
         and IS extensible: extension bit then a ONE-bit index, padded to the
         octet.  normal-call is therefore 0x40, not 0x01 and not 0x20.
  §9.2.2 RANAP-Message is an OCTET STRING: length determinant, then octets.
         The determinant is one octet below 128 and two above it, the first
         carrying 0x80 -- so a 200-octet RANAP is `80 c8` plus 200 octets.

pycrate 0.8.1's pycrate_asn1dir.RUA is the second implementation: given the
same values through its own structures it must produce the same octets, and
it must read the tool's octets back to those values.

Four defects put back into a scratch copy of the tool must each make this
check fail: the establishment-cause index widened to three bits (which turns
a normal call into an emergency call the core prioritises), the context id
widened to 32 bits, the RANAP octet string written without its determinant,
and the long-form length determinant truncated to one octet past 127.

usage: check_rua_codec.py [--tool PATH] [--negctl] [--verbose]
"""

import argparse
import os
import subprocess
import sys
import tempfile

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "rua_asn1.py")

LONG_RANAP = bytes(range(200))

# The clause statement above, as values.  Transcribed from TS 25.468, not read
# from the tool: the point of the comparison is that the two were written
# apart.
CASES = [
    {
        "name": "rua-connect-normal",
        "argv": ["connect", "--context-id", "1", "--cause", "normal-call"],
        "pycrate": (1, "ignore", "Connect", [
            (3, "reject", "Context-ID", (0x000001, 24)),
            (6, "ignore", "Establishment-Cause", "normal-call"),
        ]),
        "expect": {"procedure-name": "id-Connect", "ie.1.establishment-cause":
                   "normal-call"},
    },
    {
        "name": "rua-connect-emergency",
        "argv": ["connect", "--context-id", "1", "--cause", "emergency-call"],
        "pycrate": (1, "ignore", "Connect", [
            (3, "reject", "Context-ID", (0x000001, 24)),
            (6, "ignore", "Establishment-Cause", "emergency-call"),
        ]),
        "expect": {"procedure-name": "id-Connect", "ie.1.establishment-cause":
                   "emergency-call"},
    },
    {
        # A context id whose three octets are all non-zero, so a writer that
        # shifted the value by an octet cannot hide inside leading zeros.
        "name": "rua-transfer-context",
        "argv": ["direct-transfer", "--context-id", "0x000102",
                 "--ranap", "0000000100"],
        "pycrate": (2, "ignore", "DirectTransfer", [
            (3, "reject", "Context-ID", (0x000102, 24)),
            (4, "reject", "RANAP-Message", bytes.fromhex("0000000100")),
        ]),
        "expect": {"procedure-name": "id-DirectTransfer",
                   "ie.0.context-id": "258",
                   "ie.1.ranap": "0000000100"},
    },
    {
        # Past 127 octets the RANAP determinant grows a second octet, in both
        # the open type and the octet string.  This is the case that a
        # one-octet-only writer gets wrong while its short cases stay green.
        "name": "rua-transfer-long",
        "argv": ["direct-transfer", "--context-id", "2",
                 "--ranap", LONG_RANAP.hex()],
        "pycrate": (2, "ignore", "DirectTransfer", [
            (3, "reject", "Context-ID", (0x000002, 24)),
            (4, "reject", "RANAP-Message", LONG_RANAP),
        ]),
        "expect": {"procedure-name": "id-DirectTransfer",
                   "ie.0.context-id": "2",
                   "ie.1.ranap": LONG_RANAP.hex()},
    },
]


def load_pycrate():
    from pycrate_asn1dir import RUA
    return RUA


def pycrate_encode(RUA, procedure, criticality, typename, fields):
    """Set the PDU inside pycrate's own structures and encode aligned PER."""
    pdu = RUA.RUA_PDU_Descriptions.RUA_PDU
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


def pycrate_read(RUA, raw):
    pdu = RUA.RUA_PDU_Descriptions.RUA_PDU
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
    ("cause-index-three-bits",
     "the Establishment-Cause index widened to three bits, which reads as"
     " emergency-call",
     "    writer.bits(ESTABLISHMENT_CAUSE[name], 1)",
     "    writer.bits(ESTABLISHMENT_CAUSE[name], 3)",
     "rua-connect-normal"),
    ("context-id-thirty-two-bits",
     "the 24-bit Context-ID widened to 32 bits",
     "    writer.bits(context_id, 24)",
     "    writer.bits(context_id, 32)",
     "rua-connect-normal"),
    ("ranap-without-determinant",
     "the RANAP octet string written without its length determinant",
     "    writer.octets(_length_octets(len(raw)))\n    writer.octets(raw)",
     "    writer.octets(raw)",
     "rua-transfer-context"),
    ("long-determinant-one-octet",
     "the long form of the length determinant truncated to one octet",
     "    return bytes([0x80 | (count >> 8), count & 0xFF])",
     "    return bytes([count & 0xFF])",
     "rua-transfer-long"),
]


def check(tool, RUA, verbose=False):
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
            want = pycrate_encode(RUA, *case["pycrate"])
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-encodes" % name, False, str(exc)[:160])
            continue
        verdict("%s-octets-agree" % name, got_hex == want.hex(),
                "tool %s pycrate %s" % (got_hex, want.hex()))

        try:
            procedure, read_rows = pycrate_read(RUA, bytes.fromhex(got_hex))
        except Exception as exc:                     # noqa: BLE001
            verdict("%s-pycrate-reads" % name, False, str(exc)[:160])
            continue
        verdict("%s-pycrate-reads" % name, True)
        verdict("%s-procedure-code" % name, procedure == case["pycrate"][0],
                "read %r" % (procedure,))
        verdict("%s-ie-values" % name, read_rows == pycrate_read(RUA, want)[1],
                "read %r" % (read_rows,))

        # The tool's own decoder must agree with the writer about where each
        # IE starts: a message this tree can send and not read is half a codec.
        proc = subprocess.run([sys.executable, tool, "decode", got_hex],
                              capture_output=True, text=True)
        verdict("%s-tool-decodes" % name, proc.returncode == 0,
                proc.stderr.strip()[:160])
        if proc.returncode == 0:
            rows = dict(line.split("\t", 1) for line in proc.stdout.splitlines()
                        if "\t" in line)
            for key, want_value in case["expect"].items():
                verdict("%s-tool-%s" % (name, key),
                        rows.get(key) == want_value,
                        "read %r, wanted %r" % (rows.get(key), want_value))

    print("CASES\t%d" % (passed + failed))
    print("MISMATCHES\t%d" % failed)
    print("RESULT\t%s" % ("AGREE" if failed == 0 else "DISAGREE"))
    return failed


def negctl(RUA, verbose=False):
    """Put each defect back into a scratch copy; the check must fail on it."""
    missed = []
    with open(TOOL) as handle:
        source = handle.read()
    for name, claim, old, new, case in NEGCTL:
        if old not in source:
            missed.append((name, "the text to break is not in the tool any more"))
            print("NEGCTL\t%s\tSTALE\t%s" % (name, claim))
            continue
        handle, victim = tempfile.mkstemp(
            prefix=".rua_asn1_broken_", suffix=".py",
            dir=os.path.dirname(os.path.abspath(TOOL)))
        os.close(handle)
        try:
            with open(victim, "w") as broken:
                broken.write(source.replace(old, new, 1))
            spec = next(c for c in CASES if c["name"] == case)
            try:
                got_hex = tool_run(victim, spec["argv"])
                want = pycrate_encode(RUA, *spec["pycrate"]).hex()
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
        RUA = load_pycrate()
    except ImportError as exc:
        print("SKIP\tno pycrate RUA decoder: %s" % exc)
        return 2

    failed = check(args.tool, RUA, args.verbose)
    if args.negctl:
        missed = negctl(RUA, args.verbose)
        print("NEGCTL\t%d put back, %d missed" % (len(NEGCTL), len(missed)))
        if missed:
            failed += len(missed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
