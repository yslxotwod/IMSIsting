#!/usr/bin/env python3
"""RUA -- the RANAP User Adaptation layer of Iuh (TS 25.468), aligned PER.

The small cell already speaks HNBAP over Iuh (tools/hnbap_asn1.py).  RUA is
the other half of that interface: HNBAP registers the access point, RUA then
opens a signalling connection and carries the RANAP the core actually acts
on.  A rogue HeNB that can send a RUA Connect and a DirectTransfer with a
subscriber's RANAP inside is talking to the core, not to the phone.

What this file builds:

  Connect          procedureCode 1 -- Context-ID + Establishment-Cause
  DirectTransfer   procedureCode 2 -- Context-ID + RANAP-Message

What it does not build: the RANAP-PDU itself.  That is TS 25.413, a fourth
codec, and passing octets through a layer that does not understand them is
the difference between framing and pretending.  `--rua-transfer` takes the
RANAP as hex and says so in its output.

Layouts, each pinned against pycrate 0.8.1 and tshark 4.2.2 rather than
inferred from the clause -- see tools/rua-oracle/check_rua_codec.py.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1ap_asn1 import (  # noqa: E402
    AperWriter,
    _container,
    _criticality_octet,
)


def _length_octets(count):
    """A length determinant that survives the 128-octet boundary.

    Under 128 the determinant is one octet.  At 128 and above it is two, the
    first carrying 0x80 and the high bits of the count -- so 200 is `80 c8`.
    s1ap_asn1.length_determinant refuses the long form (nothing in S1AP it
    builds gets there), and a RANAP-Message of a real Attach plus its
    container is comfortably past 127.
    """
    if count < 0x80:
        return bytes([count])
    if count > 0xFFFF:
        raise ValueError("length %d needs fragmentation, which this file does "
                         "not write" % count)
    return bytes([0x80 | (count >> 8), count & 0xFF])


def _open_type(writer, payload):
    writer.octets(_length_octets(len(payload)))
    writer.octets(payload)


def _ie_field(ie_id, criticality, payload):
    """One ProtocolIE-Field: id, criticality, then the IE as an open type."""
    writer = AperWriter()
    writer.bits(ie_id, 16)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, payload)
    return writer.taked()


def _pdu(procedure_code, criticality, body):
    """RUA-PDU: CHOICE { initiatingMessage } then InitiatingMessage."""
    writer = AperWriter()
    writer.octet(0)                     # initiatingMessage
    writer.octet(procedure_code)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, body)
    return writer.taked()

# ---------------------------------------------------------------------------
# Constants -- TS 25.468 clause 9.
# ---------------------------------------------------------------------------

PROC_CONNECT = 1
PROC_DIRECT_TRANSFER = 2
PROC_DISCONNECT = 3

IE_CAUSE = 1
IE_CONTEXT_ID = 3
IE_RANAP_MESSAGE = 4
IE_ESTABLISHMENT_CAUSE = 6

# Establishment-Cause ::= ENUMERATED { emergency-call(0), normal-call(1) }
# extensible, so it carries an extension bit and ONE index bit.  pycrate
# lists the values in that order and tshark reads normal-call as index 1;
# writing the index in three bits yields 0x20, which decodes as
# emergency-call -- a call the core treats differently at every later step.
ESTABLISHMENT_CAUSE = {"emergency-call": 0, "normal-call": 1}

CAUSE_NAME = {0: "emergency-call", 1: "normal-call"}

PROCEDURE_NAME = {
    PROC_CONNECT: "id-Connect",
    PROC_DIRECT_TRANSFER: "id-DirectTransfer",
    PROC_DISCONNECT: "id-Disconnect",
}

IE_NAME = {
    IE_CAUSE: "id-Cause",
    IE_CONTEXT_ID: "id-Context-ID",
    IE_RANAP_MESSAGE: "id-RANAP-Message",
    IE_ESTABLISHMENT_CAUSE: "id-Establishment-Cause",
}


# ---------------------------------------------------------------------------
# IEs -- TS 25.468 clause 9.2.
# ---------------------------------------------------------------------------

def ie_context_id(context_id):
    """Context-ID ::= BIT STRING (SIZE (24)).

    A BIT STRING is not padded in aligned PER, and 24 bits is three octets
    exactly, so the value lands octet-aligned with no padding question.  The
    open type that carries it is what puts it on an octet boundary at all.
    """
    if not 0 <= context_id <= 0xFFFFFF:
        raise ValueError("Context-ID is 24 bits")
    writer = AperWriter()
    writer.bits(context_id, 24)
    return writer.taked()


def ie_establishment_cause(name):
    """Establishment-Cause ::= ENUMERATED { emergency-call, normal-call }, extensible.

    Extension bit, then the index in one bit, then padding to the octet the
    open type will hand the next IE.  normal-call is index 1, so the octet is
    0x40 -- the same shape as a criticality octet, and worth not confusing.
    """
    if name not in ESTABLISHMENT_CAUSE:
        raise ValueError("Establishment-Cause is one of %s"
                         % ", ".join(sorted(ESTABLISHMENT_CAUSE)))
    writer = AperWriter()
    writer.bit(0)                                   # no extension additions
    writer.bits(ESTABLISHMENT_CAUSE[name], 1)
    writer.align()
    return writer.taked()


def ie_ranap_message(raw):
    """RANAP-Message ::= OCTET STRING (SIZE (0..maxRANAPmSize)).

    Aligned PER writes an octet string as a length determinant followed by
    the octets -- drop the determinant and the receive side reads the first
    byte of the RANAP as the length of the rest.
    """
    writer = AperWriter()
    writer.octets(_length_octets(len(raw)))
    writer.octets(raw)
    return writer.taked()


# ---------------------------------------------------------------------------
# Messages.
# ---------------------------------------------------------------------------

def connect(context_id, cause="normal-call"):
    """Connect: the message that opens an Iuh signalling connection."""
    fields = [
        _ie_field(IE_CONTEXT_ID, "reject", ie_context_id(context_id)),
        _ie_field(IE_ESTABLISHMENT_CAUSE, "ignore", ie_establishment_cause(cause)),
    ]
    return _pdu(PROC_CONNECT, "ignore", _container(fields))


def direct_transfer(context_id, ranap):
    """DirectTransfer: a RANAP-PDU carried over the Iuh connection."""
    fields = [
        _ie_field(IE_CONTEXT_ID, "reject", ie_context_id(context_id)),
        _ie_field(IE_RANAP_MESSAGE, "reject", ie_ranap_message(ranap)),
    ]
    return _pdu(PROC_DIRECT_TRANSFER, "ignore", _container(fields))


# ---------------------------------------------------------------------------
# Decoding.
# ---------------------------------------------------------------------------

def _read_ie_length(raw, pos):
    """Open type length: one octet under 128, else the 16-bit form."""
    first = raw[pos]
    if first & 0x80:
        if pos + 1 >= len(raw):
            raise ValueError("truncated length determinant")
        return ((first & 0x7F) << 8) | raw[pos + 1], pos + 2
    return first, pos + 1


def decode(raw):
    """Walk a RUA-PDU into rows.  Generic: it does not assume one procedure."""
    if len(raw) < 4:
        raise ValueError("shorter than a RUA header")
    if raw[0] != 0x00:
        raise ValueError("not an initiating message (discriminator 0x%02x)"
                         % raw[0])
    procedure = raw[1]
    criticality = raw[2]
    body_length, body_start = _read_ie_length(raw, 3)
    body = raw[body_start:body_start + body_length]
    if len(body) < 3:
        raise ValueError("body shorter than a protocol IE container")
    count = int.from_bytes(body[1:3], "big")
    rows = [
        ("procedure", str(procedure)),
        ("procedure-name", PROCEDURE_NAME.get(procedure, "unknown")),
        ("criticality", {0x00: "reject", 0x40: "ignore", 0x80: "notify"}
         .get(criticality, "0x%02x" % criticality)),
        ("ies", str(count)),
    ]
    pos = 3
    for index in range(count):
        if pos + 4 > len(body):
            raise ValueError("IE %d starts past the end of the container" % index)
        ie_id = int.from_bytes(body[pos:pos + 2], "big")
        ie_crit = body[pos + 2]
        length, pos = _read_ie_length(body, pos + 3)
        payload = body[pos:pos + length]
        if len(payload) != length:
            raise ValueError("IE %d declares %d octets, %d present"
                             % (index, length, len(payload)))
        pos += length
        prefix = "ie.%d" % index
        rows.append((prefix + ".id", str(ie_id)))
        rows.append((prefix + ".name", IE_NAME.get(ie_id, "unknown")))
        rows.append((prefix + ".criticality",
                     {0x00: "reject", 0x40: "ignore", 0x80: "notify"}
                     .get(ie_crit, "0x%02x" % ie_crit)))
        if ie_id == IE_CONTEXT_ID:
            rows.append((prefix + ".context-id", str(int.from_bytes(payload, "big"))))
        elif ie_id == IE_ESTABLISHMENT_CAUSE:
            index_value = payload[0] >> 6 if payload else 0
            rows.append((prefix + ".establishment-cause",
                         CAUSE_NAME.get(index_value, "0x%02x" % index_value)))
        elif ie_id == IE_RANAP_MESSAGE:
            inner, start = _read_ie_length(payload, 0)
            rows.append((prefix + ".ranap", payload[start:start + inner].hex()))
            if start + inner != len(payload):
                rows.append((prefix + ".ranap-length",
                             "%d declared, %d present"
                             % (inner, len(payload) - start)))
        else:
            rows.append((prefix + ".value", payload.hex()))
    if pos != len(body):
        rows.append(("trailing", "%d octet(s) ignored" % (len(body) - pos)))
    return rows


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _emit(rows):
    for key, value in rows:
        print("%s\t%s" % (key, value))


def main(argv):
    parser = argparse.ArgumentParser(
        prog="rua_asn1.py",
        description="RUA (TS 25.468) framing for the Iuh interface")
    sub = parser.add_subparsers(dest="verb")

    p_conn = sub.add_parser("connect",
                            help="build a RUA Connect (procedureCode 1)")
    p_conn.add_argument("--context-id", type=lambda s: int(s, 0), default=1)
    p_conn.add_argument("--cause", choices=sorted(ESTABLISHMENT_CAUSE),
                        default="normal-call")

    p_dt = sub.add_parser("direct-transfer",
                          help="build a RUA DirectTransfer (procedureCode 2)")
    p_dt.add_argument("--context-id", type=lambda s: int(s, 0), default=1)
    p_dt.add_argument("--ranap", required=True,
                      help="the RANAP-PDU as hex; this file frames it, "
                           "it does not build it")

    p_dec = sub.add_parser("decode", help="walk a RUA-PDU into rows")
    p_dec.add_argument("hex")

    sub.add_parser("selftest", help="assert the layouts against fixed vectors")

    args = parser.parse_args(argv)

    if args.verb == "connect":
        _emit([("message", "Connect"),
               ("procedure", str(PROC_CONNECT)),
               ("layout", "TS 25.468 aligned PER (tools/rua_asn1.py)"),
               ("hex", connect(args.context_id, args.cause).hex())])
        return 0

    if args.verb == "direct-transfer":
        try:
            ranap = bytes.fromhex(args.ranap)
        except ValueError:
            print("ERROR\t--ranap is not hex")
            return 2
        if not ranap:
            print("ERROR\t--ranap is empty; a DirectTransfer with no RANAP "
                  "opens a connection to carry nothing")
            return 2
        _emit([("message", "DirectTransfer"),
               ("procedure", str(PROC_DIRECT_TRANSFER)),
               ("layout", "TS 25.468 aligned PER (tools/rua_asn1.py)"),
               ("ranap", "framed, not built"),
               ("hex", direct_transfer(args.context_id, ranap).hex())])
        return 0

    if args.verb == "decode":
        try:
            raw = bytes.fromhex(args.hex)
            rows = decode(raw)
        except ValueError as exc:
            print("NOTDECODED\t%s" % exc)
            return 2
        _emit(rows)
        return 0

    if args.verb == "selftest":
        return selftest()

    parser.print_help()
    return 2


# ---------------------------------------------------------------------------
# Selftest -- the vectors were produced by pycrate and confirmed by tshark.
# ---------------------------------------------------------------------------

def selftest():
    failures = []
    total = [0]

    def check(name, condition, detail=""):
        total[0] += 1
        if condition:
            print("ASSERTION\t%s\tPASS" % name)
        else:
            print("ASSERTION\t%s\tFAIL\t%s" % (name, detail))
            failures.append(name)

    connect_octets = connect(0x000001, "normal-call")
    check("connect-vector",
          connect_octets.hex() == "0001400f000002000300030000010006400140",
          connect_octets.hex())
    check("connect-octets-19", len(connect_octets) == 19, str(len(connect_octets)))

    emergency = connect(0x000001, "emergency-call")
    check("cause-emergency-is-zero",
          emergency.hex() == "0001400f000002000300030000010006400100",
          emergency.hex())

    transfer = direct_transfer(0x000102, bytes.fromhex("0000000100"))
    check("transfer-vector",
          transfer.hex() == "000240140000020003000300010200040006050000000100",
          transfer.hex())

    rows = dict(decode(connect_octets))
    check("decode-procedure", rows.get("procedure") == "1", str(rows))
    check("decode-procedure-name", rows.get("procedure-name") == "id-Connect")
    check("decode-ies", rows.get("ies") == "2")
    check("decode-context", rows.get("ie.0.context-id") == "1")
    check("decode-cause", rows.get("ie.1.establishment-cause") == "normal-call")

    rows = dict(decode(transfer))
    check("decode-transfer-name",
          rows.get("procedure-name") == "id-DirectTransfer")
    check("decode-ranap", rows.get("ie.1.ranap") == "0000000100")

    # A 200-octet RANAP crosses the 8-bit length determinant, so the open
    # type switches to the two-octet form.  If that case is wrong the reader
    # silently eats the first RANAP octet as a length.
    big = direct_transfer(0x000002, bytes(range(200)))
    check("long-ranap-octets", len(big) == 222, str(len(big)))
    check("long-ranap-head", big.hex().startswith("00024080d9"), big.hex()[:12])
    check("long-ranap-tail", big.hex().endswith("c0c1c2c3c4c5c6c7"),
          big.hex()[-16:])
    rows = dict(decode(big))
    check("long-ranap-length", len(rows.get("ie.1.ranap", "")) == 400,
          str(len(rows.get("ie.1.ranap", ""))))
    check("long-ranap-decode-head", rows.get("ie.1.ranap", "")[:2] == "00")

    # Negation: a RUA-PDU is not a RANAP-PDU and must not decode as one.
    check("rejects-non-rua", _rejects(connect_octets, 0x20))
    check("rejects-short", _rejects(connect_octets, 0x00, b"\x00\x01"))

    print("RESULT\t%s" % ("PASS" if not failures else "FAIL"))
    if failures:
        print("FAILED\t%s" % ",".join(failures))
        return 1
    print("ASSERTIONS\t%d" % total[0])
    return 0


def _rejects(good, first_octet=None, raw=None):
    """True when decoding raises -- used for the negative assertions."""
    global _count
    if raw is None:
        raw = bytearray(good)
        raw[0] = first_octet
    try:
        decode(bytes(raw))
    except ValueError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
