#!/usr/bin/env python3
"""
E2AP over APER -- RIC Control and RIC Subscription, encoded to real octets.

Why this file exists.  48_oran could describe an E2 interface and drive A1 with
real PUTs, but every E2 verb stopped at a plan line: ``--e2-control`` printed
``e2ap_procedure_code 6`` and nothing that could be put in an SCTP DATA chunk.
An E2 interface that cannot emit one encoded PDU is a document, not a
capability.  This is the encoder.

What is verified, and against what.  pycrate 0.8.1 (pycrate_asn1dir.E2AP,
release 3 ASN.1) encodes and decodes the same structures, and the vectors in
E2_VECTORS below were produced by it byte for byte.  They are asserted in
--selftest, so a change that breaks the encoding fails against an independent
implementation instead of against this file's own opinion.

The layout, in the order it is written (aligned PER, O-RAN E2AP):

    E2AP-PDU              CHOICE, extensible, 3 alternatives
                          1 extension bit, then 2 bits of index
    InitiatingMessage     SEQUENCE { procedureCode(0..255), criticality,
                                    value } -- value is an open type
    ProtocolIE-Container  SEQUENCE OF, extensible
                          1 extension bit, align, then a 16-bit count
    ProtocolIE-Field      { id(0..65535) 16 bits, criticality 2 bits,
                            value open type: align, length, octets }
    RICrequestID          SEQUENCE, extensible -> 1 preamble octet, then
                          two 16-bit integers
    RANfunctionID         0..4095 -> aligned PER spends two octets
    RICcontrolHeader/Msg  unconstrained OCTET STRING -> align, length, octets
    RICcontrolAckRequest  ENUM extensible -> extension bit, then one bit

The trap.  ``RICrequestID`` is extensible even though nothing can be added to
it, so it carries a whole preamble octet.  An encoder that treats it as a plain
SEQUENCE writes four octets where five are needed and every following IE is
shifted by an octet -- the message still parses, with a RAN function id read
out of the wrong bytes.
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# Procedure codes and IE ids the encoder emits (E2AP-Constants / -IEs).
# ---------------------------------------------------------------------------

PROC_E2SETUP = 1
PROC_RESET = 3
PROC_RICCONTROL = 4
PROC_RICSUBSCRIPTION = 8
PROC_RICSUBSCRIPTION_DELETE = 9

IE_RICREQUESTID = 29
IE_RANFUNCTIONID = 5
IE_RICCALLPROCESSID = 20
IE_RICCONTROLACKREQUEST = 21
IE_RICCONTROLHEADER = 22
IE_RICCONTROLMESSAGE = 23
IE_RICSUBSCRIPTIONDETAILS = 30

CRITICALITY = {"reject": 0, "ignore": 1, "notify": 2}


class Writer:
    """Aligned-PER writer: bits first, octets out."""

    def __init__(self):
        self._bits = []

    def bit(self, value):
        self._bits.append(1 if value else 0)
        return self

    def bits(self, value, length):
        for shift in range(length - 1, -1, -1):
            self._bits.append((value >> shift) & 1)
        return self

    def align(self):
        while len(self._bits) % 8:
            self._bits.append(0)
        return self

    def constrained(self, value, length):
        self.align()
        self.bits(value, length)
        return self.align()

    def length(self, count):
        """Aligned-PER length determinant, short form (< 128 octets)."""
        self.align()
        if count > 127:
            raise ValueError("length %d needs the long determinant form" % count)
        self.bits(count, 8)
        return self.align()

    def octets(self, data):
        self.align()
        for byte in data:
            self.bits(byte, 8)
        return self.align()

    def open_type(self, payload):
        self.length(len(payload))
        self.octets(payload)
        return self

    def taked(self):
        self.align()
        out = bytearray()
        for i in range(0, len(self._bits), 8):
            byte = 0
            for bit in self._bits[i:i + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def _ie(ie_id, criticality, payload):
    w = Writer()
    w.bits(ie_id, 16)
    w.bits(CRITICALITY[criticality], 2)
    w.open_type(payload)
    return w.taked()


def _container(fields):
    w = Writer()
    w.bit(0)                    # no extension additions
    w.constrained(len(fields), 16)
    for field in fields:
        w.octets(field)
    return w.taked()


def _pdu(procedure_code, criticality, value):
    w = Writer()
    w.bit(0)                    # E2AP-PDU extension bit
    w.bits(0, 2)                # choice 0 = initiatingMessage
    w.align()
    w.bits(procedure_code, 8)
    w.bits(CRITICALITY[criticality], 2)
    w.open_type(value)
    return w.taked()


# ---------------------------------------------------------------------------
# Individual IEs.
# ---------------------------------------------------------------------------

def ie_ric_request_id(requester, instance):
    """RICrequestID: extensible SEQUENCE, so it opens with a preamble octet."""
    if not 0 <= requester <= 0xFFFF or not 0 <= instance <= 0xFFFF:
        raise ValueError("RICrequestID fields are 0..65535")
    w = Writer()
    w.bit(0)
    w.align()
    w.bits(requester, 16)
    w.bits(instance, 16)
    return w.taked()


def ie_ran_function_id(value):
    if not 0 <= value <= 4095:
        raise ValueError("RANfunctionID is 0..4095")
    w = Writer()
    w.constrained(value, 16)
    return w.taked()


def ie_octet_string(data):
    w = Writer()
    w.length(len(data))
    w.octets(data)
    return w.taked()


def ie_ack_request(name):
    if name not in ("noAck", "ack"):
        raise ValueError("RICcontrolAckRequest is noAck or ack")
    w = Writer()
    w.bit(0)                    # extensible ENUM, no extension value
    w.bits(1 if name == "ack" else 0, 1)
    w.align()
    return w.taked()


# ---------------------------------------------------------------------------
# Messages.
# ---------------------------------------------------------------------------

def ric_control_request(requestor, instance, ran_function,
                        header, message, call_process=None, ack=None):
    """RICcontrolRequest -- what an xApp uses to drive a RAN function.

    ``header`` is the E2SM-specific control header and ``message`` the action
    itself; both are opaque here on purpose, because their meaning belongs to
    the service model, not to E2AP.
    """
    fields = [
        _ie(IE_RICREQUESTID, "reject", ie_ric_request_id(requestor, instance)),
        _ie(IE_RANFUNCTIONID, "reject", ie_ran_function_id(ran_function)),
    ]
    if call_process is not None:
        fields.append(_ie(IE_RICCALLPROCESSID, "reject", ie_octet_string(call_process)))
    fields.append(_ie(IE_RICCONTROLHEADER, "reject", ie_octet_string(header)))
    fields.append(_ie(IE_RICCONTROLMESSAGE, "reject", ie_octet_string(message)))
    if ack is not None:
        fields.append(_ie(IE_RICCONTROLACKREQUEST, "reject", ie_ack_request(ack)))
    return _pdu(PROC_RICCONTROL, "reject", _container(fields))


def ric_subscription_action(action_id, action_type, definition=None,
                            subsequent_type="continue", time_to_wait=0,
                            execution_order=None):
    """One RICaction-ToBeSetup-Item, the list element of a subscription.

    The preamble is four bits wide, not one: the item is extensible (one
    extension bit) and then carries the presence bitmap for ricActionDefinition,
    ricSubsequentAction and ricActionExecutionOrder.  A writer that emits only
    the extension bit leaves the item one octet short and every following field
    is read out of the previous one.
    """
    types = {"report": 0, "insert": 1, "policy": 2}
    if action_type not in types:
        raise ValueError("ricActionType is report, insert or policy")
    if not 0 <= action_id <= 255:
        raise ValueError("RICactionID is 0..255")
    subs = {"continue": 0, "wait": 1}
    if subsequent_type not in subs:
        raise ValueError("ricSubsequentActionType is continue or wait")
    if not 0 <= time_to_wait <= 16:
        raise ValueError("ricTimeToWait is 0..16 (w1ms..w60s)")
    w = Writer()
    w.bit(0)                    # extension bit
    w.bit(definition is not None)
    w.bit(True)                 # ricSubsequentAction is mandatory here
    w.bit(execution_order is not None)
    w.align()
    w.bits(action_id, 8)
    w.bit(0)                    # RICactionType extension bit
    w.bits(types[action_type], 2)
    w.align()
    if definition is not None:
        w.length(len(definition))
        w.octets(definition)
    # RICsubsequentAction is an extensible SEQUENCE with two mandatory fields:
    # one preamble bit, then the type (extension bit + one bit), then the time
    # to wait (extension bit + five bits).
    w.bit(0)                    # RICsubsequentAction extension bit
    w.bit(0)                    # RICsubsequentActionType extension bit
    w.bits(subs[subsequent_type], 1)
    w.bit(0)                    # RICtimeToWait extension bit
    w.bits(time_to_wait, 5)
    w.align()
    if execution_order is not None:
        w.bits(execution_order, 8)
        w.align()
    return w.taked()


def ric_subscription_details(event_trigger, actions):
    """RICsubscriptionDetails: the trigger, then the action list.

    The list is SIZE(1..16), which aligned PER spends as FOUR bits holding
    count-1, not as an eight- or sixteen-bit count.  Writing a 16-bit count
    here shifts the first list item by two octets.
    """
    if not 1 <= len(actions) <= 16:
        raise ValueError("a subscription carries 1..16 actions")
    w = Writer()
    w.bit(0)                    # extensible SEQUENCE preamble
    w.align()
    w.length(len(event_trigger))
    w.octets(event_trigger)
    w.bits(len(actions) - 1, 4)
    w.align()
    for action in actions:
        # ProtocolIE-SingleContainer: the id is fixed to 19 by the list
        item = Writer()
        item.bits(19, 16)
        item.bits(CRITICALITY["ignore"], 2)
        item.open_type(action)
        w.octets(item.taked())
    return w.taked()


def ric_subscription_request(requestor, instance, ran_function,
                             event_trigger, actions):
    fields = [
        _ie(IE_RICREQUESTID, "reject", ie_ric_request_id(requestor, instance)),
        _ie(IE_RANFUNCTIONID, "reject", ie_ran_function_id(ran_function)),
        _ie(IE_RICSUBSCRIPTIONDETAILS, "reject",
            ric_subscription_details(event_trigger, actions)),
    ]
    return _pdu(PROC_RICSUBSCRIPTION, "reject", _container(fields))


# ---------------------------------------------------------------------------
# Decoder, for reading a capture back.
# ---------------------------------------------------------------------------

class Reader:
    def __init__(self, data):
        self._bits = [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]
        self.bitpos = 0

    def bit(self):
        value = self._bits[self.bitpos]
        self.bitpos += 1
        return value

    def bits(self, length):
        value = 0
        for _ in range(length):
            value = (value << 1) | self.bit()
        return value

    def align(self):
        self.bitpos = (self.bitpos + 7) // 8 * 8
        return self

    def constrained(self, length):
        self.align()
        value = self.bits(length)
        self.align()
        return value

    def length(self):
        return self.constrained(8)

    def octets(self, count):
        self.align()
        return bytes(self.bits(8) for _ in range(count))

    def open_type(self):
        return self.octets(self.length())

    def remaining(self):
        return len(self._bits) - self.bitpos


def decode(data):
    """Decode the initiating message of an E2AP PDU into rows."""
    r = Reader(data)
    rows = []
    r.bit()                                 # PDU extension bit
    choice = r.bits(2)
    r.align()
    if choice != 0:
        raise ValueError("this decoder reads initiatingMessage only")
    proc = r.bits(8)
    crit = r.bits(2)
    rows.append(("direction", "initiatingMessage"))
    rows.append(("procedure_code", proc))
    rows.append(("criticality", list(CRITICALITY)[crit]))
    payload = r.open_type()
    if proc != PROC_RICCONTROL:
        rows.append(("payload_octets", len(payload)))
        rows.append(("note", "only RICcontrolRequest is dissected here"))
        return rows
    c = Reader(payload)
    c.bit()                                 # container extension bit
    count = c.constrained(16)
    rows.append(("ie_count", count))
    for _ in range(count):
        ie_id = c.bits(16)
        ie_crit = c.bits(2)
        value = c.open_type()
        if ie_id == IE_RICREQUESTID:
            v = Reader(value)
            v.bit()
            v.align()
            rows.append(("ric_request_id", "%d/%d" % (v.bits(16), v.bits(16))))
        elif ie_id == IE_RANFUNCTIONID:
            v = Reader(value)
            rows.append(("ran_function_id", v.constrained(16)))
        elif ie_id == IE_RICCALLPROCESSID:
            rows.append(("ric_call_process_id", value.hex().upper()))
        elif ie_id == IE_RICCONTROLHEADER:
            rows.append(("ric_control_header", value.hex().upper()))
        elif ie_id == IE_RICCONTROLMESSAGE:
            rows.append(("ric_control_message", value.hex().upper()))
        elif ie_id == IE_RICCONTROLACKREQUEST:
            rows.append(("ric_control_ack_request", "ack" if value[0] & 0x40 else "noAck"))
        else:
            rows.append(("ie_%d" % ie_id,
                         "criticality=%s value=%s" % (list(CRITICALITY)[ie_crit],
                                                      value.hex().upper())))
    if c.remaining():
        rows.append(("trailing_bits", c.remaining()))
    return rows


# ---------------------------------------------------------------------------
# Vectors produced by pycrate 0.8.1 from the same structures.
# ---------------------------------------------------------------------------

E2_VECTORS = [
    ("riccontrol-minimal",
     ric_control_request(0, 0, 0, b"", b""),
     "0004001c000004001d0005000000000000050002000000160001000017000100"),
    ("riccontrol-full",
     ric_control_request(1, 2, 2, bytes.fromhex("0102"), bytes.fromhex("aabb"),
                         ack="noAck"),
     "00040025000005001d00050000010002000500020002001600030201"
     "020017000302aabb0015000100"),
    ("ricsubscription-report",
     ric_subscription_request(7, 9, 2, bytes.fromhex("0102"),
                              [ric_subscription_action(1, "report", b"\x01")]),
     "00080026000003001d00050000070009000500020002001e00100002010200"
     "0013400760010001010000"),
    ("ricsubscription-two-actions",
     ric_subscription_request(7, 9, 2, bytes.fromhex("0102"),
                              [ric_subscription_action(1, "report", b"\x01"),
                               ric_subscription_action(2, "report", b"\x01")]),
     "00080031000003001d00050000070009000500020002001e001b0002010210"
     "00134007600100010100000013400760020001010000"),
]


def selftest():
    bad = 0
    for name, got, want in E2_VECTORS:
        if got.hex() == want:
            print("%-40s PASS" % name)
        else:
            print("%-40s FAIL want=%s got=%s" % (name, want, got.hex()))
            bad += 1
    rows = decode(E2_VECTORS[1][1])
    got = dict((k, v) for k, v in rows if not isinstance(k, int))
    if got.get("ric_request_id") == "1/2" and got.get("ran_function_id") == 2:
        print("%-40s PASS" % "decode-roundtrip")
    else:
        print("%-40s FAIL %r" % ("decode-roundtrip", rows))
        bad += 1
    print("RESULT\t%s" % ("PASS" if not bad else "FAIL(%d)" % bad))
    return 0 if not bad else 1


def main(argv):
    ap = argparse.ArgumentParser(description="E2AP APER encoder")
    ap.add_argument("--ric-control", nargs="+", metavar="ARG",
                    help="requestor instance ran-function header-hex message-hex "
                         "[call-process-hex] [noAck|ack]")
    ap.add_argument("--ric-subscribe", nargs="+", metavar="ARG",
                    help="requestor instance ran-function trigger-hex action-type "
                         "definition-hex")
    ap.add_argument("--decode", help="hex of an E2AP PDU")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()
    try:
        if a.ric_control:
            v = a.ric_control
            if len(v) < 5:
                print("ERROR\t--ric-control needs requestor instance ran-function "
                      "header-hex message-hex", file=sys.stderr)
                return 2
            call_process = None
            ack = None
            for extra in v[5:]:
                if extra in ("noAck", "ack"):
                    ack = extra
                else:
                    call_process = bytes.fromhex(extra)
            pdu = ric_control_request(int(v[0]), int(v[1]), int(v[2]),
                                      bytes.fromhex(v[3]), bytes.fromhex(v[4]),
                                      call_process=call_process, ack=ack)
            print("%s\t%s" % ("pdu", pdu.hex().upper()))
            print("%s\t%d" % ("pdu_octets", len(pdu)))
            print("%s\t%d" % ("procedure_code", PROC_RICCONTROL))
            print("procedure\tRIC Control Request")
            return 0
        if a.ric_subscribe:
            v = a.ric_subscribe
            if len(v) < 6:
                print("ERROR\t--ric-subscribe needs requestor instance ran-function "
                      "trigger-hex action-type definition-hex", file=sys.stderr)
                return 2
            action = ric_subscription_action(1, v[4], bytes.fromhex(v[5]))
            pdu = ric_subscription_request(int(v[0]), int(v[1]), int(v[2]),
                                           bytes.fromhex(v[3]), [action])
            print("%s\t%s" % ("pdu", pdu.hex().upper()))
            print("%s\t%d" % ("pdu_octets", len(pdu)))
            print("%s\t%d" % ("procedure_code", PROC_RICSUBSCRIPTION))
            print("procedure\tRIC Subscription Request")
            return 0
        if a.decode:
            for key, value in decode(bytes.fromhex(a.decode)):
                print("%s\t%s" % (key, value))
            return 0
    except (ValueError, IndexError) as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 2
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
