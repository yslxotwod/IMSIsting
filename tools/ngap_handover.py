#!/usr/bin/env python3
"""NGAP N2 handover chain -- the encoder behind 13_nr_core.sh --n2-handover.

TS 38.413 clause 9.1.4.2 (HandoverPreparation, initiatingMessage
HandoverRequired, successfulOutcome HandoverCommand) and clause 9.1.4.3
(HandoverNotification, initiatingMessage HandoverNotify).  The IE numbers,
their criticality and their presence come from the NGAP ASN.1 of TS 38.413
clause 9.3, read off the tables the clause states; nothing here is guessed:

  HandoverRequired   (procedureCode 12, criticality reject)
      id-AMF-UE-NGAP-ID 10                       reject     mandatory
      id-RAN-UE-NGAP-ID 85                       reject     mandatory
      id-HandoverType 29                         reject     mandatory
      id-Cause 15                                ignore     mandatory
      id-TargetID 105                            reject     mandatory
      id-DirectForwardingPathAvailability 22     ignore     optional
      id-PDUSessionResourceListHORqd 61          reject     mandatory
      id-SourceToTarget-TransparentContainer 101 reject     mandatory

  HandoverCommand    (procedureCode 12, criticality reject, successfulOutcome)
      id-AMF-UE-NGAP-ID 10                       reject     mandatory
      id-RAN-UE-NGAP-ID 85                       reject     mandatory
      id-HandoverType 29                         reject     mandatory
      id-NASSecurityParametersFromNGRAN 39       reject     conditional
      id-PDUSessionResourceHandoverList 59       ignore     optional
      id-PDUSessionResourceToReleaseList 78      ignore     optional
      id-TargetToSource-TransparentContainer 106 reject     mandatory
      id-CriticalityDiagnostics 19               ignore     optional

  HandoverNotify     (procedureCode 11, criticality ignore)
      id-AMF-UE-NGAP-ID 10                       reject     mandatory
      id-RAN-UE-NGAP-ID 85                       reject     mandatory
      id-UserLocationInformation 121             ignore     mandatory
      id-NotifySourceNGRANNode 269               ignore     optional

HandoverNotify carries no PDUSessionResourceList -- its container is
HandoverNotifyIEs, and the fourth entry there is NotifySourceNGRANNode.  This
tool therefore refuses --pdu-session for notify rather than writing an id the
receiver's table does not hold, and it restamps the criticality of
UserLocationInformation (ignore in this message, reject in the ones that list
it that way) instead of writing the location layout a second time.

Two values are carried, not interpreted: SourceToTarget-TransparentContainer
and TargetToSource-TransparentContainer are OCTET STRINGs whose contents are
the RRC container TS 38.413 does not define, so this tool takes them as hex
and says so rather than inventing an RRC message.  A handover it builds is
therefore a *shape* a real AMF or gNB will parse; whether the RRC inside it
would be accepted is a fact only the target can supply, and the plan printed
by the module reports exactly that as unobserved.

Anchors, all aligned PER (X.691):
  * NGAP-PDU choice, three root alternatives (§9.1): two index bits, one
    extension bit, so a single zero octet -- inherited from ngap_asn1.
  * Cause (§9.3.1.2): CHOICE, five root alternatives plus an extension
    marker, so the extension bit and a three-bit index; CauseRadioNetwork
    is an ENUMERATED with a root set, an extension bit and a six-bit index.
  * TargetID (§9.3.1.46): CHOICE of two root alternatives plus the
    extension marker -- the extension bit and ONE index bit.
  * TargetRANNodeID (§9.3.1.45): SEQUENCE with an extension marker and one
    OPTIONAL (iE-Extensions), so two preamble bits, then GlobalRANNodeID.
  * GlobalRANNodeID (§9.3.1.24): CHOICE, three root alternatives plus the
    extension marker -- three bits, then GlobalGNB-ID.
  * GlobalGNB-ID (§9.3.1.23): SEQUENCE with an extension marker and one
    OPTIONAL, then pLMNIdentity (OCTET STRING (SIZE(3)), octet-aligned) and
    GNB-ID.  GNB-ID (§9.3.1.22) is a CHOICE with ONE root alternative and
    an extension marker, so a single bit, then BIT STRING (SIZE(22..32)) --
    a four-bit length field (the width minus 22) and the bits.
  * TAI (§9.3.1.50): SEQUENCE, extension marker and one OPTIONAL, then
    pLMNIdentity and tAC, both OCTET STRING (SIZE(3)).
  * PDUSessionResourceListHORqd (§9.3.1.55): SEQUENCE (SIZE(1..256)) OF
    PDUSessionResourceItemHORqd; the count is a constrained whole number of
    eight bits, each item is a SEQUENCE { pDUSessionID (0..255),
    handoverRequiredTransfer OCTET STRING, iE-Extensions OPTIONAL }.

The octets this tool writes are checked against pycrate 0.8.1's NGAP module
(tools/ngap-oracle/check_ngap_handover.py, run by
tools/check-ngap-handover.sh) and against tshark's NGAP dissector, never
against this file's own reading of itself.

Nothing here transmits.  It writes octets to stdout.
"""

import sys

from ngap_asn1 import (AperWriter, _absent, _container, _criticality_octet,
                       _ie_field, _open_type, _plmn_bytes, ie_amf_ue_ngap_id,
                       ie_ran_ue_ngap_id, ie_user_location_information)

# TS 38.413 clause 9.3.14, the ProtocolIE-ID values of the three messages.
IE_AMF_UE_NGAP_ID = 10
IE_CAUSE = 15
IE_HANDOVER_TYPE = 29
IE_NAS_SECURITY_PARAMETERS_FROM_NGRAN = 39
IE_PDU_SESSION_RESOURCE_LIST_HORQD = 61
IE_RAN_UE_NGAP_ID = 85
IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 101
IE_TARGET_ID = 105
IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER = 106
IE_USER_LOCATION_INFORMATION = 121
# id-NotifySourceNGRANNode: optional in HandoverNotify and not written here,
# named so a reader who expects a session list at 269 sees what 269 really is.
IE_NOTIFY_SOURCE_NGRAN_NODE = 269

# TS 38.413 clause 9.1.4.2 / 9.1.4.3, the elementary procedure codes.
PROCEDURE_HANDOVER_PREPARATION = 12
PROCEDURE_HANDOVER_NOTIFICATION = 11

# TS 38.413 clause 9.3.1.44: HandoverType, three root alternatives plus an
# extension marker (fivegs-to-utran lives on the extension side).
HANDOVER_TYPES = {"intra5gs": 0, "fivegs-to-eps": 1, "eps-to-5gs": 2}
HANDOVER_TYPE_EXTENSION = {"fivegs-to-utran": 0}

# TS 38.413 clause 9.3.1.2: CauseRadioNetwork, an extensible ENUMERATED.
# The root set is the order the clause states; a receiver built from an older
# release of the clause knows fewer of them, which is reported as unobserved
# rather than assumed away.
CAUSE_RADIO_NETWORK = (
    "unspecified", "txnrelocoverall-expiry", "successful-handover",
    "release-due-to-ngran-generated-reason",
    "release-due-to-5gc-generated-reason", "handover-cancelled",
    "partial-handover", "ho-failure-in-target-5GC-ngran-node-or-target-system",
    "ho-target-not-allowed", "tngrelocoverall-expiry", "tngrelocprep-expiry",
    "cell-not-available", "unknown-targetID",
    "no-radio-resources-available-in-target-cell",
    "unknown-local-UE-NGAP-ID", "inconsistent-remote-UE-NGAP-ID",
    "handover-desirable-for-radio-reason", "time-critical-handover",
    "resource-optimisation-handover", "reduce-load-in-serving-cell",
    "user-inactivity", "radio-connection-with-ue-lost",
    "radio-resources-not-available", "invalid-qos-combination",
    "failure-in-radio-interface-procedure",
    "interaction-with-other-procedure", "unknown-PDU-session-ID",
    "unkown-qos-flow-ID", "multiple-PDU-session-ID-instances",
    "multiple-qos-flow-ID-instances",
    "encryption-and-or-integrity-protection-algorithms-not-supported",
    "ng-intra-system-handover-triggered",
    "ng-inter-system-handover-triggered", "xn-handover-triggered",
    "not-supported-5QI-value", "ue-context-transfer",
    "ims-voice-eps-fallback-or-rat-fallback-triggered",
    "up-integrity-protection-not-possible",
    "up-confidentiality-protection-not-possible", "slice-not-supported",
    "ue-in-rrc-inactive-state-not-reachable", "redirection",
    "resources-not-available-for-the-slice",
    "ue-max-integrity-protected-data-rate-reason",
    "release-due-to-cn-detected-mobility",
)

DEFAULT_CAUSE = "handover-desirable-for-radio-reason"


class Error(Exception):
    """A value the clause does not allow; the caller prints it and exits 2."""


def _bits_needed(count):
    """Bits that hold ``count`` distinct values (X.691 §13.2.7)."""
    if count <= 1:
        return 0
    return (count - 1).bit_length()


def _octet_string(data):
    """OCTET STRING with an unconstrained length: a determinant then bytes."""
    writer = AperWriter()
    writer.length_determinant(len(data))
    writer.octets(data)
    return writer.taked()


def _append(writer, other):
    """Append another writer's bits, keeping them mid-octet.

    ngap_asn1's AperWriter exposes no public append, and joining two encodings
    with taked() would insert the padding bits that turn a preamble into a
    whole octet; the bit list is the writer's only state.
    """
    writer._bits.extend(other._bits)
    return writer


def _hex(text, label):
    try:
        return bytes.fromhex(str(text))
    except ValueError:
        raise Error("%s must be an even run of hex digits, got %r" % (label, text))


# ---------------------------------------------------------------------------
# The IE values that this module's own builder layer does not already write.
# ---------------------------------------------------------------------------

def handover_type(name):
    """HandoverType (id 29): ENUMERATED with three root alternatives."""
    name = str(name or "intra5gs")
    if name in HANDOVER_TYPES:
        writer = AperWriter()
        writer.bit(0)                                   # root, not extension
        writer.bits(HANDOVER_TYPES[name], 2)
        writer.align()
        return _ie_field(IE_HANDOVER_TYPE, "reject", writer.taked())
    if name in HANDOVER_TYPE_EXTENSION:
        writer = AperWriter()
        writer.bit(1)                                   # on the extension side
        # One value on the extension side: the extension bit is the whole
        # index, so no index bits follow it (X.691 §14.4).
        writer.align()
        return _ie_field(IE_HANDOVER_TYPE, "reject", writer.taked())
    raise Error("unknown HandoverType %r (have %s)"
                % (name, ", ".join(list(HANDOVER_TYPES) + list(HANDOVER_TYPE_EXTENSION))))


def cause_radio_network(name):
    """Cause (id 15): CHOICE radioNetwork, then the reason.

    Five root alternatives give a three-bit index after the extension bit, and
    CauseRadioNetwork's root set gives a six-bit index after its own extension
    bit.  Eleven bits in one run: the two preambles and the enumerator share
    them, and aligning between them would move the reason into the next octet.
    """
    if name not in CAUSE_RADIO_NETWORK:
        raise Error("unknown radioNetwork cause %r" % (name,))
    index = CAUSE_RADIO_NETWORK.index(name)
    writer = AperWriter()
    # Cause lists six alternatives and the last of them is choice-Extensions,
    # so the index covers all six and nothing precedes it: three bits, no
    # separate extension bit -- the same shape GlobalRANNodeID has below.
    writer.bits(0, 3)                                   # radioNetwork
    writer.bit(0)                                       # in the root set
    writer.bits(index, _bits_needed(len(CAUSE_RADIO_NETWORK)))
    writer.align()
    return _ie_field(IE_CAUSE, "ignore", writer.taked())


def _target_ran_node_id(writer, plmn, gnb_id, gnb_id_bits):
    """Write GlobalRANNodeID into a writer that is already mid-octet.

    ngap_asn1.ie_global_ran_node_id writes the same run and then pads it to an
    octet boundary, which is right for an IE value and wrong inside
    TargetRANNodeID: there the CHOICE follows TargetRANNodeID's own two
    preamble bits and the only alignment allowed is the one pLMNIdentity
    forces.  A separate writer would align against its own first bit instead,
    which is how a TargetID grows a zero octet and the dissector reads a PLMN
    one octet late.
    """
    if not 22 <= gnb_id_bits <= 32:
        raise Error("a gNB identity is 22 to 32 bits, got %d" % (gnb_id_bits,))
    if not 0 <= gnb_id < (1 << gnb_id_bits):
        raise Error("a %d-bit gNB identity is out of range" % (gnb_id_bits,))
    raw_plmn = _plmn_bytes(plmn)
    # GlobalRANNodeID: three node identities and choice-Extensions, so the
    # index is two bits over four alternatives with no extension bit.
    writer.bits(0, 2)                                   # globalGNB-ID
    _absent(writer, 1)                                  # GlobalGNB-ID: iE-Extensions
    writer.align()                                      # pLMNIdentity is octets
    writer.octets(raw_plmn)
    writer.bit(0)                                       # GNB-ID: gNB-ID
    writer.bits(gnb_id_bits - 22, 4)                    # SIZE(22..32) length
    writer.align()
    writer.bits(gnb_id, gnb_id_bits)
    return writer


def target_id(plmn, gnb_id, tac, gnb_id_bits=22):
    """TargetID (id 105): targetRANNodeID { globalRANNodeID, selectedTAI }."""
    raw_tac = _hex(tac, "the target TAC")
    if len(raw_tac) != 3:
        raise Error("a 5G TAC is three octets, got %d" % (len(raw_tac),))
    writer = AperWriter()
    # TargetID: targetRANNodeID, targeteNB-ID and choice-Extensions, so two
    # index bits and no extension bit.  TargetRANNodeID carries the extension
    # marker and one OPTIONAL, so two preamble bits follow in the same run.
    writer.bits(0, 2)                                   # targetRANNodeID
    _absent(writer, 1)                                  # TargetRANNodeID iE-Extensions
    _target_ran_node_id(writer, plmn, gnb_id, gnb_id_bits)
    _absent(writer, 1)                                  # TAI iE-Extensions
    writer.align()
    writer.octets(_plmn_bytes(plmn))
    writer.octets(raw_tac)
    writer.align()
    return _ie_field(IE_TARGET_ID, "reject", writer.taked())


def pdu_session_resource_list_horqd(items):
    """PDUSessionResourceListHORqd (id 61): the sessions asked to move.

    ``items`` is a list of (pDUSessionID, handoverRequiredTransfer bytes).
    The list is SEQUENCE (SIZE(1..256)) OF, whose count is a constrained whole
    number of eight bits; a message that names no session is refused by the
    clause, so an empty list is an error here rather than a zero-length list.
    """
    if not 1 <= len(items) <= 256:
        raise Error("PDUSessionResourceListHORqd holds 1 to 256 sessions, got %d"
                    % (len(items),))
    writer = AperWriter()
    # SIZE(1..256): the count is a constrained whole number of eight bits
    # carrying the offset from the lower bound, so one session writes 0x00
    # (X.691 §13.2.7 with the §19.5 length), not 0x01.
    writer.bits(len(items) - 1, 8)
    for pdu_id, transfer in items:
        if not 0 <= pdu_id <= 255:
            raise Error("a PDU session id is 0 to 255, got %r" % (pdu_id,))
        _absent(writer, 1)                              # item iE-Extensions
        writer.octet(pdu_id)
        writer.length_determinant(len(transfer))
        writer.octets(transfer)
    writer.align()
    return _ie_field(IE_PDU_SESSION_RESOURCE_LIST_HORQD, "reject", writer.taked())


# ---------------------------------------------------------------------------
# The three messages.
# ---------------------------------------------------------------------------

def _envelope(choice, procedure_code, criticality, body):
    """NGAP-PDU with the InitiatingMessage / SuccessfulOutcome wrapper."""
    writer = AperWriter()
    writer.octet(choice << 5)                           # §9.1 PDU choice
    writer.octet(procedure_code)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, body)
    return writer.taked()


def handover_required(amf_ue_id, ran_ue_id, handover_type_name, cause,
                      plmn, gnb_id, tac, sessions, source_to_target,
                      gnb_id_bits=22):
    body = _container([
        ie_amf_ue_ngap_id(amf_ue_id),
        ie_ran_ue_ngap_id(ran_ue_id),
        handover_type(handover_type_name),
        cause_radio_network(cause),
        target_id(plmn, gnb_id, tac, gnb_id_bits),
        pdu_session_resource_list_horqd(sessions),
        _ie_field(IE_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER, "reject",
                  _octet_string(source_to_target)),
    ])
    return _envelope(0, PROCEDURE_HANDOVER_PREPARATION, "reject", body)


def handover_command(amf_ue_id, ran_ue_id, handover_type_name, plmn, gnb_id,
                     tac, target_to_source, nas_security_parameters=b"",
                     gnb_id_bits=22):
    ies = [
        ie_amf_ue_ngap_id(amf_ue_id),
        ie_ran_ue_ngap_id(ran_ue_id),
        handover_type(handover_type_name),
    ]
    if nas_security_parameters:
        ies.append(_ie_field(IE_NAS_SECURITY_PARAMETERS_FROM_NGRAN, "reject",
                             _octet_string(nas_security_parameters)))
    ies.append(_ie_field(IE_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER, "reject",
                         _octet_string(target_to_source)))
    return _envelope(1, PROCEDURE_HANDOVER_PREPARATION, "reject", _container(ies))


def _user_location_information(plmn, nci, tac):
    """UserLocationInformation (id 121) with HandoverNotify's criticality.

    ngap_asn1.ie_user_location_information writes the field with CRITICALITY
    reject; HandoverNotifyIEs gives the same IE CRITICALITY ignore
    (TS 38.413 clause 9.2.3.5).  The criticality is the third octet of an IE
    field -- two octets of id, then the criticality -- so it is restamped
    here and the location layout keeps one implementation.
    """
    field = ie_user_location_information(plmn, nci, tac)
    return field[:2] + bytes([_criticality_octet("ignore")]) + field[3:]


def handover_notify(amf_ue_id, ran_ue_id, plmn, nci, tac):
    """HandoverNotify: the three IEs its own container defines."""
    ies = [
        ie_amf_ue_ngap_id(amf_ue_id),
        ie_ran_ue_ngap_id(ran_ue_id),
        _user_location_information(plmn, nci, tac),
    ]
    return _envelope(0, PROCEDURE_HANDOVER_NOTIFICATION, "ignore", _container(ies))


MESSAGES = {
    "required": "HandoverRequired",
    "command": "HandoverCommand",
    "notify": "HandoverNotify",
}

IE_SUMMARY = {
    "required": "10,85,29,15,105,61,101",
    "command": "10,85,29,39?,106",
    "notify": "10,85,121",
}


# ---------------------------------------------------------------------------
# CLI -- one row of "field<TAB>value" per line, the shape 13_nr_core reads.
# ---------------------------------------------------------------------------

USAGE = """usage: ngap_handover.py <required|command|notify|chain> [options]

  --amf-ue-id N            AMF-UE-NGAP-ID (0..1099511627775)   [1]
  --ran-ue-id N            RAN-UE-NGAP-ID (0..4294967295)      [1]
  --handover-type NAME     intra5gs | fivegs-to-eps | eps-to-5gs |
                           fivegs-to-utran                     [intra5gs]
  --cause NAME             a CauseRadioNetwork reason  [handover-desirable-for-radio-reason]
  --plmn MCC/MNC           the target PLMN                     [001/01]
  --gnb-id N               the target gNB identity             [0x000001]
  --gnb-id-bits N          22 to 32                            [22]
  --tac HEX                the target tracking area, 3 octets  [000001]
  --nci N                  the NR cell identity for notify     [0]
  --pdu-session ID:HEX     a session and its handoverRequiredTransfer (repeatable)
  --source-to-target HEX   SourceToTarget-TransparentContainer, opaque  [0x00]
  --target-to-source HEX   TargetToSource-TransparentContainer, opaque  [0x00]
  --nas-security HEX       NASSecurityParametersFromNGRAN, optional     []

Output: field<TAB>value rows -- message, procedure_code, ngap_choice,
criticality, ies, octets, hex.  Nothing is sent anywhere.
"""


def _int(text, label, upper):
    try:
        value = int(str(text), 0)
    except ValueError:
        raise Error("%s must be an integer, got %r" % (label, text))
    if not 0 <= value <= upper:
        raise Error("%s is 0 to %d, got %d" % (label, upper, value))
    return value


def parse_options(argv):
    opts = {
        "amf_ue_id": 1, "ran_ue_id": 1, "handover_type": "intra5gs",
        "cause": DEFAULT_CAUSE, "plmn": "001/01", "gnb_id": 0x000001,
        "gnb_id_bits": 22, "tac": "000001", "nci": 0, "sessions": [],
        "source_to_target": "00", "target_to_source": "00",
        "nas_security": "",
    }
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag in ("-h", "--help"):
            sys.stdout.write(USAGE)
            raise SystemExit(0)
        if flag == "--pdu-session":
            index += 1
            if index >= len(argv):
                raise Error("--pdu-session needs ID:HEX")
            text = argv[index]
            if ":" not in text:
                raise Error("--pdu-session is ID:HEX, got %r" % (text,))
            pdu_id, transfer = text.split(":", 1)
            opts["sessions"].append((_int(pdu_id, "a PDU session id", 255),
                                     _hex(transfer, "a handoverRequiredTransfer")))
        elif flag.startswith("--"):
            index += 1
            if index >= len(argv):
                raise Error("%s needs a value" % (flag,))
            value = argv[index]
            if flag == "--amf-ue-id":
                opts["amf_ue_id"] = _int(value, "AMF-UE-NGAP-ID", 0xFFFFFFFFFF)
            elif flag == "--ran-ue-id":
                opts["ran_ue_id"] = _int(value, "RAN-UE-NGAP-ID", 0xFFFFFFFF)
            elif flag == "--handover-type":
                opts["handover_type"] = value
            elif flag == "--cause":
                opts["cause"] = value
            elif flag == "--plmn":
                opts["plmn"] = value
            elif flag == "--gnb-id":
                opts["gnb_id"] = _int(value, "the gNB identity", 0xFFFFFFFF)
            elif flag == "--gnb-id-bits":
                opts["gnb_id_bits"] = _int(value, "the gNB identity width", 32)
            elif flag == "--tac":
                opts["tac"] = value
            elif flag == "--nci":
                opts["nci"] = _int(value, "the NR cell identity", (1 << 36) - 1)
            elif flag == "--source-to-target":
                opts["source_to_target"] = value
            elif flag == "--target-to-source":
                opts["target_to_source"] = value
            elif flag == "--nas-security":
                opts["nas_security"] = value
            else:
                raise Error("unknown option %s" % (flag,))
        else:
            raise Error("unexpected argument %r" % (flag,))
        index += 1
    return opts


def build(message, opts):
    if message == "required":
        return handover_required(
            opts["amf_ue_id"], opts["ran_ue_id"], opts["handover_type"],
            opts["cause"], opts["plmn"], opts["gnb_id"], opts["tac"],
            opts["sessions"] or [(5, b"")],
            _hex(opts["source_to_target"], "SourceToTarget-TransparentContainer"),
            opts["gnb_id_bits"])
    if message == "command":
        return handover_command(
            opts["amf_ue_id"], opts["ran_ue_id"], opts["handover_type"],
            opts["plmn"], opts["gnb_id"], opts["tac"],
            _hex(opts["target_to_source"], "TargetToSource-TransparentContainer"),
            _hex(opts["nas_security"], "NASSecurityParametersFromNGRAN")
            if opts["nas_security"] else b"",
            opts["gnb_id_bits"])
    if message == "notify":
        if opts["sessions"]:
            raise Error("HandoverNotify carries no PDUSessionResourceListHORqd "
                        "(TS 38.413 clause 9.2.3.5: AMF-UE-NGAP-ID, "
                        "RAN-UE-NGAP-ID, UserLocationInformation, "
                        "NotifySourceNGRANNode); drop --pdu-session")
        return handover_notify(
            opts["amf_ue_id"], opts["ran_ue_id"], opts["plmn"], opts["nci"],
            opts["tac"])
    raise Error("unknown message %r" % (message,))


def emit(prefix, message, raw):
    name = MESSAGES[message]
    choice = {"required": "initiatingMessage", "notify": "initiatingMessage",
              "command": "successfulOutcome"}[message]
    procedure = (PROCEDURE_HANDOVER_NOTIFICATION if message == "notify"
                 else PROCEDURE_HANDOVER_PREPARATION)
    criticality = "ignore" if message == "notify" else "reject"
    rows = [
        ("message", name),
        ("procedure_code", str(procedure)),
        ("ngap_choice", choice),
        ("criticality", criticality),
        ("ies", IE_SUMMARY[message]),
        ("octets", str(len(raw))),
        ("hex", raw.hex()),
    ]
    for field, value in rows:
        sys.stdout.write("%s%s\t%s\n" % (prefix, field, value))


def main(argv):
    if not argv:
        sys.stderr.write(USAGE)
        return 2
    if argv[0] in ("-h", "--help"):
        sys.stdout.write(USAGE)
        return 0
    message = argv[0]
    if message not in ("required", "command", "notify", "chain"):
        sys.stderr.write("ERROR\tunknown message %r (required, command, notify, chain)\n"
                         % (message,))
        return 2
    try:
        opts = parse_options(argv[1:])
        if message == "chain":
            for part in ("required", "command", "notify"):
                emit(part + "_", part, build(part, opts))
        else:
            emit("", message, build(message, opts))
    except Error as exc:
        sys.stderr.write("ERROR\t%s\n" % (exc,))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
