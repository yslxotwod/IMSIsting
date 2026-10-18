#!/usr/bin/env python3
"""
NGAP over APER -- TS 38.413 message bodies, encoded to real octets.

Why this is a separate file from tools/s1ap_asn1.py even though both are
aligned PER: they are different protocols with different IE registries, and
the one thing they share is the PER machinery, which is imported rather than
copied.  A subscriber's attach on the 5G core is an NGAP message the same way
it is an S1AP message on the 4G core; before this file the tree could decode
NGAP (modules/13_nr_core.sh --ngap-decode) and could not write a single one,
so every "the core would accept this" claim about the 5G side was made from a
S1AP message translated by hand.

What is verified and how.  Every vector in VECTORS was produced by pycrate
0.8.1 (pycrate_asn1dir.NGAP), an independent transcription of the same ASN.1,
and by this file, and the two agree to the octet -- tools/ngap-oracle/
re-runs that comparison.  Every vector was then replayed through tshark 4.2.2
as an SCTP DATA chunk with PPID 60 and dissected from scratch, which is the
second referee.  The structures tshark printed are in the comments.

IE status, and it is split deliberately:

  RAN-UE-NGAP-ID      VERIFIED    id 85, INTEGER (0..4294967295).  The width
  AMF-UE-NGAP-ID                  rule is APER's, and it is not one rule: the
                                  length of the value sits in as many bits as
                                  the range needs, so a 32-bit range spends
                                  two bits and a 40-bit range spends three.
                                  AMF-UE-NGAP-ID 256 is 20 01 00 -- three
                                  bits of length (001) then 0100 -- while the
                                  same value in S1AP's four-octet range is
                                  40 01 00.  Copying the S1AP rule here
                                  gives an IE that a dissector reads as zero.
  NAS-PDU             VERIFIED    id 38, an unconstrained OCTET STRING: one
                                  length octet, then the bytes.
  UEPagingIdentity    VERIFIED    id 115, CHOICE carrying 5G-S-TMSI.  The
                                  extension bit, the CHOICE index and the
                                  SEQUENCE's iE-Extensions bit are three bits
                                  in one run; AMFSetID (10 bits) and
                                  AMFPointer (6 bits) follow as bit-fields
                                  with NO octet alignment between them, and
                                  only the 4-octet 5G-TMSI inside them starts
                                  on an octet boundary.
  TAIListForPaging    VERIFIED    id 103, SEQUENCE (SIZE(1..16)) OF TAI.  The
                                  count is four bits; each TAI is one
                                  iE-Extensions bit, an alignment, then
                                  pLMNIdentity and a THREE-octet TAC.  A
                                  two-octet TAC -- the 4G width -- decodes
                                  here as a truncated tracking area.

What these messages are not, stated because a fragment that decodes is easy
to mistake for a complete message:

  InitialUEMessage    also requires UserLocationInformation (id 121) and
                      RRCEstablishmentCause (id 90).  Neither is built, so
                      this is a fragment that a dissector reads without a
                      Malformed verdict and a real AMF would reject.
  Paging              also requires TAIListForPaging, which IS built; it is
                      the one whole message here.

The envelope rules this file rides on -- the PDU CHOICE discriminator, the
16-bit container count, the open-type framing, the criticality octet -- are
the same in both protocols and are asserted here rather than assumed,
because the one place they differ (the INTEGER width above) is exactly the
kind of difference a shared helper hides.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1ap_asn1 import AperReader, AperWriter  # noqa: E402  one PER, not two

# ---------------------------------------------------------------------------
# TS 38.413 clause 9.3 -- IE ids this file emits.
# ---------------------------------------------------------------------------

IE_AMF_UE_NGAP_ID = 10
IE_GLOBAL_RAN_NODE_ID = 27
IE_NAS_PDU = 38
IE_RAN_NODE_NAME = 82
IE_RAN_UE_NGAP_ID = 85
IE_RRC_ESTABLISHMENT_CAUSE = 90
IE_SUPPORTED_TA_LIST = 102
IE_TAI_LIST_FOR_PAGING = 103
IE_UEPAGING_IDENTITY = 115
IE_USER_LOCATION_INFORMATION = 121

PROC_DOWNLINK_NAS = 4
PROC_INITIAL_UE = 15
PROC_NG_SETUP = 21
PROC_PAGING = 24

# ENUMERATED { reject, ignore, notify, ... }: extension flag in the top bit,
# index in the two below it.  Same octets as S1AP, same trap.
CRITICALITY = {"reject": 0x00, "ignore": 0x40, "notify": 0x80}
CRITICALITY_NAME = {v: k for k, v in CRITICALITY.items()}


def _criticality_octet(name):
    if name not in CRITICALITY:
        raise ValueError("criticality must be one of %s" % ", ".join(CRITICALITY))
    return CRITICALITY[name]


# ---------------------------------------------------------------------------
# Container helpers -- the message body.
# ---------------------------------------------------------------------------

def _open_type(writer, payload):
    writer.length_determinant(len(payload))
    writer.octets(payload)


def _ie_field(ie_id, criticality, payload):
    """One ProtocolIE-Field: id, criticality, then the IE as an open type."""
    writer = AperWriter()
    writer.bits(ie_id, 16)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, payload)
    return writer.taked()


def _container(ie_fields):
    """ProtocolIE-Container: SEQUENCE (SIZE(0..65535)) OF ProtocolIE-Field.

    The SEQUENCE carries an extension marker, so its preamble is one bit and
    it is padded before the count.  The count itself is constrained at
    0..65535 and is therefore sixteen bits -- not a length determinant.  A
    one-octet count parses, reports zero IEs and silently ignores the body,
    which reads like success.
    """
    writer = AperWriter()
    writer.bit(0)                       # no extension additions present
    writer.align()
    writer.constrained_count(len(ie_fields), 16)
    for field in ie_fields:
        writer.octets(field)
    return writer.taked()


# ---------------------------------------------------------------------------
# The INTEGER rule, which is the one place NGAP and S1AP disagree.
# ---------------------------------------------------------------------------

def _constrained_uint(value, upper, label):
    """A constrained INTEGER, aligned PER.

    The value goes in the fewest octets that hold it; above them sits a
    length field whose WIDTH depends on the range, not on the protocol.  A
    range of 2**32 values needs four octets at most, so the length is two
    bits; a 2**40 range needs five, so the length is three bits.  Getting the
    width from the value instead of the range is how AMF-UE-NGAP-ID 256 turns
    into 00 01 00 and decodes as zero.
    """
    if not 0 <= value <= upper:
        raise ValueError("%s is a 0..%d integer" % (label, upper))
    widest = max(1, upper.bit_length() // 8 + (1 if upper.bit_length() % 8 else 0))
    length_bits = (widest - 1).bit_length()
    count = 1 if value == 0 else (value.bit_length() + 7) // 8
    writer = AperWriter()
    writer.bits(count - 1, length_bits)
    writer.align()
    writer.octets(value.to_bytes(count, "big"))
    return writer.taked()


# ---------------------------------------------------------------------------
# Individual IEs -- TS 38.413 clause 9.3.x.
# ---------------------------------------------------------------------------

def ie_ran_ue_ngap_id(value):
    """RAN-UE-NGAP-ID: INTEGER (0..4294967295), two-bit length."""
    return _ie_field(IE_RAN_UE_NGAP_ID, "reject",
                     _constrained_uint(value, 0xFFFFFFFF, "RAN-UE-NGAP-ID"))


def ie_amf_ue_ngap_id(value):
    """AMF-UE-NGAP-ID: INTEGER (0..1099511627775), THREE-bit length."""
    return _ie_field(IE_AMF_UE_NGAP_ID, "reject",
                     _constrained_uint(value, 0xFFFFFFFFFF, "AMF-UE-NGAP-ID"))


def ie_nas_pdu(nas):
    """NAS-PDU: OCTET STRING, a length determinant then the bytes."""
    writer = AperWriter()
    writer.length_determinant(len(nas))
    writer.octets(nas)
    return _ie_field(IE_NAS_PDU, "reject", writer.taked())


def ie_ue_paging_identity(amf_set_id, amf_pointer, tmsi):
    """UEPagingIdentity: CHOICE { fiveG-S-TMSI }, the only root alternative.

    Three bits open it: the CHOICE's extension marker, the choice of
    fiveG-S-TMSI within the root, and FiveG-S-TMSI's own iE-Extensions bit.
    AMFSetID (SIZE(10)) and AMFPointer (SIZE(6)) then run together as
    bit-fields -- sixteen bits, no alignment between them, which is why they
    are written as one run here -- and the 4-octet 5G-TMSI starts on the
    octet boundary after them.
    """
    if not 0 <= amf_set_id < (1 << 10):
        raise ValueError("an AMF Set ID is ten bits")
    if not 0 <= amf_pointer < (1 << 6):
        raise ValueError("an AMF Pointer is six bits")
    if len(tmsi) != 4:
        raise ValueError("a 5G-TMSI is four octets")
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bit(0)                       # CHOICE: fiveG-S-TMSI
    writer.bit(0)                       # FiveG-S-TMSI has no iE-Extensions
    writer.bits(amf_set_id, 10)
    writer.bits(amf_pointer, 6)
    writer.align()                      # the TMSI starts on its own octet
    writer.octets(tmsi)
    return _ie_field(IE_UEPAGING_IDENTITY, "ignore", writer.taked())


def ie_tai_list_for_paging(tais):
    """TAIListForPaging: SEQUENCE (SIZE(1..16)) OF TAI.

    The count is four bits because the size constraint is 1..16 and the count
    is the value minus the lower bound.  Each TAI is { pLMNidentity, tAC
    OCTET STRING(SIZE(3)), iE-Extensions OPTIONAL }: one preamble bit for the
    absent extensions, an alignment, three octets of PLMN, three of TAC.
    The first item's preamble bit shares the count's octet -- writing the
    count, aligning, then the bit spends a whole octet on zeroes, which a
    dissector reads as an empty tracking area.  The
    TAC is three octets in 5G and two in 4G; taking the 4G width here leaves
    the last octet of the tracking area to be read as the next item.
    """
    if not 1 <= len(tais) <= 16:
        raise ValueError("TAIListForPaging holds 1..16 tracking areas")
    writer = AperWriter()
    writer.bits(len(tais) - 1, 4)
    writer.bit(0)                       # the first TAI's iE-Extensions bit
    writer.align()                      # count and that bit share one octet
    for index, (plmn, tac) in enumerate(tais):
        raw_tac = bytes.fromhex(str(tac))
        if len(raw_tac) != 3:
            raise ValueError("a 5G TAC is three octets, got %r" % (tac,))
        if index:
            writer.bit(0)               # a later TAI opens its own octet
            writer.align()
        writer.octets(_plmn_bytes(plmn))
        writer.octets(raw_tac)
    return _ie_field(IE_TAI_LIST_FOR_PAGING, "ignore", writer.taked())


# ---------------------------------------------------------------------------
# The IEs that make an InitialUEMessage whole, and the setup request before it.
#
# Every layout below was read off pycrate 0.8.1 and replayed through tshark;
# the ones whose item-to-item packing could not be proven are refused with an
# error naming the limit rather than guessed (see _supported_ta_list).
# ---------------------------------------------------------------------------

def _absent(writer, optional_bits):
    """The extension bit and one bit per optional member, all absent.

    No alignment: a preamble is bits, and a caller that aligns after each
    nested SEQUENCE spends an octet per SEQUENCE -- which is how a location
    report grows a zero octet that a dissector reads as an empty field.
    """
    writer.bit(0)
    for _ in range(optional_bits):
        writer.bit(0)
    return writer


def ie_user_location_information(plmn, nci, tac):
    """UserLocationInformation (id 121): where the handset says it is.

    CHOICE { userLocationInformationEUTRA, userLocationInformationNR,
    userLocationInformationN3IWF-with-PortNumber }: two bits of index, taken
    here as the second alternative.  The chosen SEQUENCE is
    { nR-CGI, tAI, timeStamp OPTIONAL, iE-Extensions OPTIONAL }, the CGI is
    { pLMNIdentity, nRCellIdentity BIT STRING (SIZE(36)), iE-Extensions
    OPTIONAL } and the TAI is { pLMNIdentity, tAC OCTET STRING(SIZE(3)),
    iE-Extensions OPTIONAL }.

    Three preamble runs come first (the CHOICE index, UserLocationInformation
    NR's two member bits, NR-CGI's one) and they share ONE octet, then the
    cell identity is a fixed 36 bits, then the TAI's own two preamble bits
    land in the padding after it.  Aligning after each run instead spends two
    extra octets on zeroes and the report still dissects -- as a location
    with fields that are not there.
    """
    if not 0 <= nci < (1 << 36):
        raise ValueError("an NR cell identity is 36 bits")
    raw_tac = bytes.fromhex(str(tac))
    if len(raw_tac) != 3:
        raise ValueError("a 5G TAC is three octets, got %r" % (tac,))
    writer = AperWriter()
    writer.bits(1, 2)                   # CHOICE: userLocationInformationNR
    _absent(writer, 2)                  # timeStamp and iE-Extensions absent
    _absent(writer, 1)                  # NR-CGI: iE-Extensions absent
    writer.align()
    writer.octets(_plmn_bytes(plmn))
    writer.bits(nci, 36)                # fixed size: no length field
    _absent(writer, 1)                  # TAI: iE-Extensions absent
    writer.align()
    writer.octets(_plmn_bytes(plmn))
    writer.octets(raw_tac)
    return _ie_field(IE_USER_LOCATION_INFORMATION, "reject", writer.taked())


CAUSES = [
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling",
    "mo-Data", "mo-VoiceCall", "mo-VideoCall", "mo-SMS", "mps-PriorityAccess",
    "mcs-PriorityAccess",
]


def ie_rrc_establishment_cause(cause):
    """RRCEstablishmentCause (id 90): an extensible ENUMERATED.

    Ten root values, so the index needs four bits and the extension bit sits
    above them: mo-Data is 0x20, mo-Signalling 0x18, emergency 0x00.  One
    octet, criticality ignore -- a cause a node does not recognise is not a
    reason to drop the message.
    """
    if cause not in CAUSES:
        raise ValueError("cause must be one of %s" % ", ".join(CAUSES))
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bits(CAUSES.index(cause), 4)
    writer.align()
    return _ie_field(IE_RRC_ESTABLISHMENT_CAUSE, "ignore", writer.taked())


def ie_global_ran_node_id(plmn, gnb_id, gnb_id_bits=22):
    """GlobalRANNodeID (id 27): CHOICE { globalGNB-ID, ... }.

    GN B-ID is CHOICE { gNB-ID BIT STRING (SIZE(22..32)) }: one choice bit,
    then a FOUR-bit length (the value minus 22), then the alignment the
    length forces, then the bits themselves.  A 32-bit identity opens the
    value with 0x50, which is how that length field's position was pinned.
    """
    if not 22 <= gnb_id_bits <= 32:
        raise ValueError("a gNB identity is 22 to 32 bits")
    if not 0 <= gnb_id < (1 << gnb_id_bits):
        raise ValueError("a %d-bit gNB identity is out of range" % gnb_id_bits)
    writer = AperWriter()
    writer.bits(0, 2)                   # CHOICE: globalGNB-ID
    _absent(writer, 1)                  # GlobalGNB-ID: iE-Extensions absent
    writer.align()
    writer.octets(_plmn_bytes(plmn))
    writer.bit(0)                       # GN B-ID CHOICE: gNB-ID
    writer.bits(gnb_id_bits - 22, 4)
    writer.align()
    writer.bits(gnb_id, gnb_id_bits)
    writer.align()
    return _ie_field(IE_GLOBAL_RAN_NODE_ID, "reject", writer.taked())


def ie_ran_node_name(name):
    """RANNodeName (id 82): PrintableString (SIZE(1..150), ...).

    An extensible size constraint, so the length field is the extension bit
    followed by the length minus one in eight bits, padded to two octets:
    six characters give 02 80, one gives 00 00.  The other order (length
    first, extension bit after) produces 05 00, which reads as a name of
    length six to a dissector with no extension support -- and as an
    extended form to one that has it.
    """
    raw = str(name).encode("ascii")
    if not 1 <= len(raw) <= 150:
        raise ValueError("a RAN node name is 1..150 characters")
    writer = AperWriter()
    writer.bit(0)                       # the size constraint's extension bit
    writer.bits(len(raw) - 1, 8)
    writer.align()
    writer.octets(raw)
    return _ie_field(IE_RAN_NODE_NAME, "ignore", writer.taked())


def _slice_support_list(sst):
    """SliceSupportList with exactly ONE slice, carrying only an SST.

    SEQUENCE (SIZE(1..65535)) OF SliceSupportItem: a sixteen-bit count, then
    SliceSupportItem { s-NSSAI, iE-Extensions OPTIONAL } -- two preamble bits
    -- then S-NSSAI { sST, sD OPTIONAL, iE-Extensions OPTIONAL } -- three
    more -- then the one-octet SST.  Thirteen bits, two octets, and the SST
    is the last eight of them: writing it as an octet aligns first and the
    item becomes three.  A second item starts mid octet, which is why this
    refuses more than one.
    """
    if not 0 <= sst <= 0xFF:
        raise ValueError("an SST is one octet")
    writer = AperWriter()
    writer.bits(0, 16)                  # count - 1: a single slice
    _absent(writer, 1)                  # SliceSupportItem: iE-Extensions
    _absent(writer, 2)                  # S-NSSAI: sD and iE-Extensions
    writer.bits(sst, 8)                 # no alignment: the item is 13 bits
    return writer.taked()


def _broadcast_plmn_list(plmns, sst):
    """BroadcastPLMNList: SEQUENCE (SIZE(1..12)) OF BroadcastPLMNItem.

    The count is four bits (the value minus one) and the first item's two
    preamble bits share that octet, so a two-PLMN list opens with 0x10 and a
    one-PLMN list with 0x00.
    """
    if not 1 <= len(plmns) <= 12:
        raise ValueError("BroadcastPLMNList holds 1..12 PLMNs")
    writer = AperWriter()
    writer.bits(len(plmns) - 1, 4)
    for index, plmn in enumerate(plmns):
        if index:
            writer.align()
        _absent(writer, 1)
        writer.align()
        writer.octets(_plmn_bytes(plmn))
        writer.octets(_slice_support_list(sst))
    return writer.taked()


def _supported_ta_list(tac, plmns, sst):
    """SupportedTAList with exactly ONE tracking area.

    SEQUENCE (SIZE(1..maxnoofTACs)) OF SupportedTAItem, and a single item is
    thirteen octets -- count, item preamble, three of TAC, eight of the
    broadcast PLMN list -- which is what pycrate and tshark both agree on.
    Two items do not: the second item's preamble does not land where the
    count's padding implies and no clause statement settled which width is
    right, so this refuses instead of emitting octets only pycrate can read.
    """
    raw_tac = bytes.fromhex(str(tac))
    if len(raw_tac) != 3:
        raise ValueError("a 5G TAC is three octets, got %r" % (tac,))
    writer = AperWriter()
    writer.octet(0)                     # count - 1: one tracking area
    _absent(writer, 1)                  # SupportedTAItem: iE-Extensions
    writer.align()
    writer.octets(raw_tac)
    writer.octets(_broadcast_plmn_list(plmns, sst))
    return writer.taked()


def ng_setup_request(plmn, gnb_id, node_name, tac, gnb_id_bits=22, sst=1):
    """NGSetupRequest: the gNB's first message, TNL association established.

    Three IEs: GlobalRANNodeID (27), RANNodeName (82) and SupportedTAList
    (102).  Everything an AMF answers on N2 hangs off these, so an AMF that
    accepts the association without them has not been checked.
    """
    if not 0 <= sst <= 0xFF:
        raise ValueError("an SST is one octet")
    fields = [
        ie_global_ran_node_id(plmn, gnb_id, gnb_id_bits),
        ie_ran_node_name(node_name),
        _ie_field(IE_SUPPORTED_TA_LIST, "reject",
                  _supported_ta_list(tac, [plmn], sst)),
    ]
    return _pdu(PROC_NG_SETUP, "reject", _container(fields))


def _plmn_bytes(plmn):
    """PLMNidentity: MCC2|MCC1, MNC3|MCC3, MNC2|MNC1, a nibble of F for a
    two-digit MNC.  Same rule as S1AP and TS 24.008 10.5.1.3."""
    if isinstance(plmn, str) and "/" in plmn:
        mcc, mnc = plmn.split("/", 1)
    elif isinstance(plmn, (tuple, list)) and len(plmn) == 2:
        mcc, mnc = plmn
    else:
        raise ValueError("a PLMN is MCC/MNC or (mcc, mnc)")
    mcc, mnc = str(mcc).zfill(3), str(mnc)
    if len(mcc) != 3:
        raise ValueError("MCC must be three digits")
    if len(mnc) not in (2, 3):
        raise ValueError("MNC must be two or three digits")
    mnc3 = mnc[2] if len(mnc) == 3 else "f"
    return bytes.fromhex("%s%s%s%s%s%s" % (mcc[1], mcc[0], mnc3, mcc[2], mnc[1], mnc[0]))


# ---------------------------------------------------------------------------
# PDUs -- the NGAP-PDU envelope, TS 38.413 clause 9.1.
# ---------------------------------------------------------------------------

def _pdu(procedure_code, criticality, body):
    """NGAP-PDU: CHOICE { initiatingMessage, successfulOutcome,
    unsuccessfulOutcome, ... }.

    Three root alternatives and an extension marker: two bits of index and one
    of extension, all zero, padded to the single octet 0x00.  The
    InitiatingMessage that follows is a plain SEQUENCE with no marker and no
    optionals, so it has no preamble: procedureCode, criticality, then the
    body as an open type.
    """
    writer = AperWriter()
    writer.octet(0)
    writer.octet(procedure_code)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, body)
    return writer.taked()


def initial_ue_message(ran_ue_id, nas, location=None, cause=None):
    """InitialUEMessage: the gNB's first word about a handset.

    RAN-UE-NGAP-ID and NAS-PDU always; UserLocationInformation (id 121) and
    RRCEstablishmentCause (id 90) are mandatory in the clause and are written
    when the caller supplies them -- `location` is a (plmn, nci, tac)
    triple, `cause` one of CAUSES.  Left out, they are named as missing
    rather than filled with a plausible-looking zero: a made-up cell
    identity inside a location report is a claim about where a subscriber
    is, and a made-up cause is a claim about what they were doing.
    """
    fields = [
        ie_ran_ue_ngap_id(ran_ue_id),
        ie_nas_pdu(nas),
    ]
    if location is not None:
        plmn, nci, tac = location
        fields.append(ie_user_location_information(plmn, nci, tac))
    if cause is not None:
        fields.append(ie_rrc_establishment_cause(cause))
    return _pdu(PROC_INITIAL_UE, "reject", _container(fields))


def downlink_nas_transport(amf_ue_id, ran_ue_id, nas):
    """DownlinkNASTransport: the core's word back, three mandatory IEs."""
    fields = [
        ie_amf_ue_ngap_id(amf_ue_id),
        ie_ran_ue_ngap_id(ran_ue_id),
        ie_nas_pdu(nas),
    ]
    return _pdu(PROC_DOWNLINK_NAS, "reject", _container(fields))


def paging(amf_set_id, amf_pointer, tmsi, tais):
    """Paging: the identity being called and the areas it is called in.

    Criticality is ignore on both IEs -- a paging block a node does not
    understand is not a reason to drop the procedure.
    """
    fields = [
        ie_ue_paging_identity(amf_set_id, amf_pointer, tmsi),
        ie_tai_list_for_paging(tais),
    ]
    return _pdu(PROC_PAGING, "ignore", _container(fields))


# ---------------------------------------------------------------------------
# Decoder -- enough of the envelope and the IEs above to read back what this
# file writes, and to name an IE it does not know instead of guessing.
# ---------------------------------------------------------------------------

IE_NAMES = {
    IE_RAN_UE_NGAP_ID: "RAN-UE-NGAP-ID",
    IE_AMF_UE_NGAP_ID: "AMF-UE-NGAP-ID",
    IE_GLOBAL_RAN_NODE_ID: "GlobalRANNodeID",
    IE_NAS_PDU: "NAS-PDU",
    IE_RAN_NODE_NAME: "RANNodeName",
    IE_RRC_ESTABLISHMENT_CAUSE: "RRCEstablishmentCause",
    IE_SUPPORTED_TA_LIST: "SupportedTAList",
    IE_UEPAGING_IDENTITY: "UEPagingIdentity",
    IE_TAI_LIST_FOR_PAGING: "TAIListForPaging",
    IE_USER_LOCATION_INFORMATION: "UserLocationInformation",
}

PROCEDURE_NAMES = {
    PROC_DOWNLINK_NAS: "DownlinkNASTransport",
    PROC_INITIAL_UE: "InitialUEMessage",
    PROC_NG_SETUP: "NGSetupRequest",
    PROC_PAGING: "Paging",
}


def _plmn_text(raw):
    if len(raw) != 3:
        return raw.hex()
    a, b, c = raw
    mcc = "%d%d%d" % (a & 0x0F, a >> 4, b & 0x0F)
    third = b >> 4
    mnc = "%d%d" % (c & 0x0F, c >> 4) if third == 0x0F else "%d%d%d" % (c & 0x0F, third, c >> 4)
    return "%s/%s" % (mcc, mnc)


def _decode_ie(reader, ie_id):
    if ie_id in (IE_RAN_UE_NGAP_ID, IE_AMF_UE_NGAP_ID):
        upper = 0xFFFFFFFF if ie_id == IE_RAN_UE_NGAP_ID else 0xFFFFFFFFFF
        widest = max(1, upper.bit_length() // 8 + (1 if upper.bit_length() % 8 else 0))
        length_bits = (widest - 1).bit_length()
        width = (reader.bits(length_bits) + 1) * 8
        reader.align()
        return str(reader.bits(width)), reader
    if ie_id == IE_NAS_PDU:
        count = reader.octet()
        return reader.octets(count).hex(), reader
    if ie_id == IE_UEPAGING_IDENTITY:
        if reader.bit() != 0:
            return "extended form (not decoded here)", reader
        if reader.bit() != 0:
            return "unknown paging identity choice", reader
        reader.bit()                    # FiveG-S-TMSI iE-Extensions
        amf_set_id = reader.bits(10)
        amf_pointer = reader.bits(6)
        reader.align()
        tmsi = reader.octets(4).hex()
        return "5g-s-tmsi set=%d pointer=%d tmsi=%s" % (amf_set_id, amf_pointer, tmsi), reader
    if ie_id == IE_TAI_LIST_FOR_PAGING:
        count = reader.bits(4) + 1
        reader.bit()                    # the first TAI's iE-Extensions bit
        reader.align()
        parts = []
        for index in range(count):
            if index:
                reader.bit()
                reader.align()
            plmn = _plmn_text(reader.octets(3))
            tac = reader.octets(3).hex()
            parts.append("%s %s" % (plmn, tac))
        return " ".join(parts), reader
    if ie_id == IE_USER_LOCATION_INFORMATION:
        choice = reader.bits(2)
        if choice != 1:
            return "location choice %d (not decoded here)" % choice, reader
        reader.bit()                    # UserLocationInformationNR extension
        reader.bit()                    # timeStamp absent
        reader.bit()                    # iE-Extensions absent
        reader.bit()                    # NR-CGI extension
        reader.bit()                    # NR-CGI iE-Extensions absent
        reader.align()                  # the two runs share one octet
        cell_plmn = _plmn_text(reader.octets(3))
        nci = reader.bits(36)
        reader.bit()                    # TAI extension
        reader.bit()                    # TAI iE-Extensions absent
        reader.align()
        tai_plmn = _plmn_text(reader.octets(3))
        tac = reader.octets(3).hex()
        return ("nrcgi %s %09x tai %s %s" % (cell_plmn, nci, tai_plmn, tac)), reader
    if ie_id == IE_RRC_ESTABLISHMENT_CAUSE:
        if reader.bit() != 0:
            return "extended cause (not decoded here)", reader
        index = reader.bits(4)
        reader.align()
        if index < len(CAUSES):
            return CAUSES[index], reader
        return "cause index %d (not in the root list)" % index, reader
    if ie_id == IE_RAN_NODE_NAME:
        if reader.bit() != 0:
            return "extended name form (not decoded here)", reader
        length = reader.bits(8) + 1
        reader.align()
        return reader.octets(length).decode("ascii", "replace"), reader
    if ie_id == IE_GLOBAL_RAN_NODE_ID:
        choice = reader.bits(2)
        if choice != 0:
            return "global RAN node choice %d (not decoded here)" % choice, reader
        reader.bit()                    # GlobalGNB-ID extension
        reader.bit()                    # iE-Extensions absent
        reader.align()
        plmn = _plmn_text(reader.octets(3))
        if reader.bit() != 0:
            return "%s gnb-id choice unknown" % plmn, reader
        width = reader.bits(4) + 22
        reader.align()
        gnb_id = reader.bits(width)
        return "gnb %s %0*x (%d bits)" % (plmn, (width + 3) // 4, gnb_id, width), reader
    if ie_id == IE_SUPPORTED_TA_LIST:
        if reader.octet() != 0:
            return "more than one tracking area (not decoded here)", reader
        reader.bit()                    # SupportedTAItem extension
        reader.bit()                    # iE-Extensions absent
        reader.align()
        tac = reader.octets(3).hex()
        plmn_count = reader.bits(4) + 1
        parts = []
        for index in range(plmn_count):
            if index:
                reader.align()
            reader.bit()                # BroadcastPLMNItem extension
            reader.bit()                # iE-Extensions absent
            reader.align()
            plmn = _plmn_text(reader.octets(3))
            slices = reader.bits(16) + 1
            ssts = []
            for _ in range(slices):
                reader.bit()            # SliceSupportItem extension
                reader.bit()            # iE-Extensions absent
                reader.bit()            # S-NSSAI extension
                reader.bit()            # sD absent
                reader.bit()            # iE-Extensions absent
                ssts.append(reader.bits(8))
            parts.append("%s sst %s" % (plmn, " ".join("%02x" % s for s in ssts)))
        return "tac %s %s" % (tac, ", ".join(parts)), reader
    raise ValueError("no decoder for IE id %d" % ie_id)


def decode(raw):
    """Return a list of (key, value) rows for one NGAP-PDU."""
    if len(raw) < 4:
        raise ValueError("too short to be an NGAP-PDU")
    reader = AperReader(raw)
    discriminator = reader.octet()
    if discriminator != 0:
        raise ValueError("only initiating messages are decoded (%#x)" % discriminator)
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
    inner.bit()                         # the container's extension marker
    inner.align()
    count = inner.bits(16)
    inner.align()
    rows.append(("ies", "%d" % count))
    for _ in range(count):
        ie_id = inner.bits(16)
        inner.align()
        ie_criticality = CRITICALITY_NAME.get(inner.octet(), "?")
        ie_len = inner.octet()
        value_bytes = inner.octets(ie_len)
        name = IE_NAMES.get(ie_id, "IE-%d" % ie_id)
        try:
            text, _ = _decode_ie(AperReader(value_bytes), ie_id)
        except Exception as exc:
            text = "undecodable (%s)" % exc
        rows.append(("ie", "%s %s %s" % (name, ie_criticality, text)))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _emit(hexbody):
    print("pdu\tNGAP")
    print("octets\t%d" % (len(hexbody) // 2))
    print("hex\t%s" % hexbody)


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("initial-ue", help="InitialUEMessage")
    p.add_argument("--ran-ue-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--nas", required=True)
    p.add_argument("--cell", help="NR cell identity in hex; adds the location IE")
    p.add_argument("--nci", type=lambda v: int(v, 0), help="NR cell identity as a number")
    p.add_argument("--plmn", default="001/01", help="MCC/MNC for the location IE")
    p.add_argument("--tac", default="000001", help="tracking area code, hex")
    p.add_argument("--cause", choices=CAUSES, help="adds the establishment cause IE")

    p = sub.add_parser("downlink-nas", help="DownlinkNASTransport")
    p.add_argument("--amf-ue-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--ran-ue-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--nas", required=True)

    p = sub.add_parser("paging", help="Paging")
    p.add_argument("--amf-set-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--amf-pointer", type=lambda v: int(v, 0), default=0)
    p.add_argument("--tmsi", required=True, help="four octets of hex")
    p.add_argument("--tai", action="append", required=True,
                   help="MCC/MNC/TAC in hex, e.g. 001/01/000001")

    p = sub.add_parser("ng-setup", help="NGSetupRequest")
    p.add_argument("--plmn", default="001/01", help="MCC/MNC")
    p.add_argument("--gnb-id", type=lambda v: int(v, 0), default=0xA1C01)
    p.add_argument("--gnb-id-bits", type=int, default=22)
    p.add_argument("--node-name", default="LabGNb")
    p.add_argument("--tac", default="000001", help="three octets of hex")
    p.add_argument("--sst", type=lambda v: int(v, 0), default=1)

    p = sub.add_parser("decode", help="decode one NGAP-PDU from hex")
    p.add_argument("hex")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)
    try:
        if args.verb == "initial-ue":
            location = None
            if args.cell is not None or args.nci is not None:
                nci = args.nci if args.nci is not None else int(args.cell.replace(":", ""), 16) & 0xFFFFFFFFF
                location = (args.plmn, nci, args.tac)
            _emit(initial_ue_message(args.ran_ue_id, bytes.fromhex(args.nas),
                                     location=location, cause=args.cause).hex())
        elif args.verb == "downlink-nas":
            _emit(downlink_nas_transport(args.amf_ue_id, args.ran_ue_id,
                                         bytes.fromhex(args.nas)).hex())
        elif args.verb == "paging":
            tais = []
            for spec in args.tai:
                plmn, tac = spec.rsplit("/", 1)
                tais.append((plmn, tac))
            _emit(paging(args.amf_set_id, args.amf_pointer,
                         bytes.fromhex(args.tmsi), tais).hex())
        elif args.verb == "ng-setup":
            _emit(ng_setup_request(args.plmn, args.gnb_id, args.node_name,
                                   args.tac, args.gnb_id_bits, args.sst).hex())
        elif args.verb == "decode":
            for key, value in decode(bytes.fromhex(args.hex)):
                print("%s\t%s" % (key, value))
        elif args.verb == "selftest":
            return selftest()
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# Vectors.  Each hex below was produced by pycrate 0.8.1 and by this file
# before it was written down; tools/ngap-oracle/ re-checks the first claim and
# tshark 4.2.2 re-checks the second.  The structure tshark printed is in the
# comment.
# ---------------------------------------------------------------------------

VECTORS = [
    # RAN-UE-NGAP-ID 1: two bits of length, then one octet of value.
    ("ran-ue-id-1", "005500020001", "RAN-UE-NGAP-ID 1"),
    # The finding: a 40-bit range spends three bits of length, so 256 is
    # 20 01 00 here and 40 01 00 in S1AP's 32-bit range.
    ("amf-ue-id-256", "000a0003200100", "AMF-UE-NGAP-ID 256, three bits of length"),
    # NAS-PDU 7e005b01 -- a 5G Identity Request, one length octet then bytes.
    ("nas-pdu", "00260005047e005b01", "NAS-PDU 7e005b01"),
    # tshark: id-InitialUEMessage (15), id-RAN-UE-NGAP-ID 1, id-NAS-PDU and
    # inside it a NAS-5GS Registration request (0x41), no Malformed verdict.
    ("initial-ue-full",
     "000f001500000200550002000100260008077e0041012e0100",
     "InitialUEMessage RAN-UE 1 NAS 7e0041012e0100"),
    # tshark: id-DownlinkNASTransport (4), AMF-UE-NGAP-ID 256, RAN-UE 1, and
    # a NAS-5GS Identity request (0x5b).  The downlink vector carries an
    # Identity Request because a Registration Request is an uplink message
    # and the NAS-5GS dissector says so -- the check does not paper over
    # direction to make two verdicts agree.
    ("downlink-nas-full",
     "00040019000003000a000320010000550002000100260005047e005b01",
     "DownlinkNASTransport AMF-UE 256 RAN-UE 1 NAS 7e005b01"),
    # tshark: id-Paging (24), id-UEPagingIdentity, id-TAIListForPaging with
    # pLMNIdentity 00f110 and tAC 1.
    ("paging-full",
     "00184019000002007340070008000a0b0c0d006740070000f110000001",
     "Paging 5g-s-tmsi set 1 ptr 0 tmsi 0a0b0c0d TAI 001/01 000001"),
    # tshark: id-InitialUEMessage (15) with FOUR IEs -- RAN-UE-NGAP-ID 1,
    # NAS-PDU, id-UserLocationInformation (121) dissected down to
    # nRCellIdentity 0x123456789 and tAC 1, and id-RRCEstablishmentCause (90)
    # "mo-Data (4)".  The only Malformed verdict on the wire is the NAS-5GS
    # dissector's on the 074100 filler, which is not a NAS message.
    ("initial-ue-located",
     "000f002900000400550002000100260004030741000079000f4000f110123456789000f110000001005a400120",
     "InitialUEMessage RAN-UE 1 NAS 074100 location 001/01 0x123456789 TAC 1 mo-Data"),
    # tshark: id-NGSetup (21) with GlobalRANNodeID (27) globalGNB-ID, PLMN
    # 00f110, gNB-ID 22 bits 0x0a1c01; RANNodeName (82) "LabGnb";
    # SupportedTAList (102) with tAC 1, one broadcast PLMN, one slice sST 01.
    # Zero Malformed verdicts on the whole frame.
    ("ng-setup-full",
     "0015002c000003001b00080000f110002870040052400802804c6162476e620066000d00000000010000f11000000008",
     "NGSetupRequest gNB 001/01 0x0a1c01 name LabGnb TAC 000001 sst 01"),
]

NAS_UPLINK = b"\x7e\x00\x41\x01\x2e\x01\x00"
NAS_DOWNLINK = b"\x7e\x00\x5b\x01"


def selftest():
    """Encode what we can, then read it back with our own decoder, then check
    the bytes against the vectors that two referees agreed on.

    The decoder is not an independent check of the encoder -- they are two
    halves of one file, and a bit error mirrored in both passes.  The
    independent half is tools/ngap-oracle/check_ngap_codec.py, which asks
    pycrate to encode the same messages from the clause tables and compares.
    """
    passed = 0
    failed = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print("%s\tPASS" % name)
        else:
            failed += 1
            print("%s\tFAIL\t%s" % (name, detail))

    by_name = {row[0]: row[1] for row in VECTORS}

    check("plmn-001-01", _plmn_bytes("001/01").hex() == "00f110",
          _plmn_bytes("001/01").hex())
    check("plmn-310-260", _plmn_bytes("310/260").hex() == "130062",
          _plmn_bytes("310/260").hex())
    check("plmn-two-digit", _plmn_bytes("001/01").hex() == "00f110")
    check("criticality-reject", _criticality_octet("reject") == 0x00)
    check("criticality-ignore", _criticality_octet("ignore") == 0x40)
    check("criticality-notify", _criticality_octet("notify") == 0x80)

    check("encode-ran-ue-id-1", ie_ran_ue_ngap_id(1).hex() == by_name["ran-ue-id-1"],
          ie_ran_ue_ngap_id(1).hex())
    check("encode-amf-ue-id-256", ie_amf_ue_ngap_id(256).hex() == by_name["amf-ue-id-256"],
          ie_amf_ue_ngap_id(256).hex())
    check("amf-length-is-three-bits",
          ie_amf_ue_ngap_id(256).hex()[8:10] == "20",
          "AMF-UE-NGAP-ID 256 must open 20, not 40")
    check("ran-length-is-two-bits",
          ie_ran_ue_ngap_id(256).hex()[8:10] == "40",
          "RAN-UE-NGAP-ID 256 opens 40: a 32-bit range spends two bits")
    check("encode-nas-pdu", ie_nas_pdu(NAS_DOWNLINK).hex() == by_name["nas-pdu"],
          ie_nas_pdu(NAS_DOWNLINK).hex())
    check("encode-initial-ue",
          initial_ue_message(1, NAS_UPLINK).hex() == by_name["initial-ue-full"],
          initial_ue_message(1, NAS_UPLINK).hex())
    check("encode-downlink-nas",
          downlink_nas_transport(256, 1, NAS_DOWNLINK).hex()
          == by_name["downlink-nas-full"],
          downlink_nas_transport(256, 1, NAS_DOWNLINK).hex())
    check("encode-paging",
          paging(1, 0, bytes.fromhex("0a0b0c0d"), [("001/01", "000001")]).hex()
          == by_name["paging-full"],
          paging(1, 0, bytes.fromhex("0a0b0c0d"), [("001/01", "000001")]).hex())

    # The container count is the silent failure: one octet still parses, and
    # reports an empty IE list while the body is ignored.
    body = _container([ie_nas_pdu(NAS_DOWNLINK)])
    check("container-count-is-16-bit", body[1:3] == b"\x00\x01", body[:4].hex())
    check("container-has-extension-bit", body[0] == 0x00)

    # A three-octet TAC: a two-octet one shifts the next item's PLMN.
    tais = ie_tai_list_for_paging([("001/01", "000001")])
    check("tai-list-three-octet-tac", tais.hex().endswith("00f110000001"),
          tais.hex())
    for bad in ("0001", "00000001"):
        try:
            ie_tai_list_for_paging([("001/01", bad)])
            ok = False
        except ValueError:
            ok = True
        check("tai-rejects-%d-octet-tac" % (len(bad) // 2), ok)

    three = {
        "initial-ue-full": ("InitialUEMessage", "RAN-UE-NGAP-ID reject 1"),
        "downlink-nas-full": ("DownlinkNASTransport", "AMF-UE-NGAP-ID reject 256"),
        "paging-full": ("Paging", "0a0b0c0d"),
    }
    for name, (procedure, needle) in three.items():
        rows = decode(bytes.fromhex(by_name[name]))
        head = dict(rows)
        check("decode-%s-procedure" % name, head.get("procedure") == procedure,
              str(head.get("procedure")))
        blob = " ".join(v for k, v in rows if k == "ie")
        check("decode-%s-ie" % name, needle in blob, blob)
    paging_rows = decode(bytes.fromhex(by_name["paging-full"]))
    joined = " ".join(v for k, v in paging_rows if k == "ie")
    check("decode-paging-tai", "001/01 000001" in joined, joined)
    check("decode-paging-no-undecodable", "undecodable" not in joined, joined)

    # An IE this file does not know is named, not guessed at and not fatal.
    unknown = _ie_field(999, "ignore", b"\x00")
    rows = decode(_pdu(PROC_PAGING, "ignore", _container([unknown])))
    blob = " ".join(v for k, v in rows if k == "ie")
    check("decode-unknown-ie-named", "IE-999" in blob, blob)


    # ---- the IEs that make an InitialUEMessage whole, and the setup request.
    located = initial_ue_message(1, bytes.fromhex("074100"),
                                 location=("001/01", 0x123456789, "000001"),
                                 cause="mo-Data")
    check("encode-initial-ue-located", located.hex() == by_name["initial-ue-located"],
          located.hex())
    check("encode-ng-setup", ng_setup_request("001/01", 0x0A1C01, "LabGnb", "000001").hex()
          == by_name["ng-setup-full"],
          ng_setup_request("001/01", 0x0A1C01, "LabGnb", "000001").hex())

    uli = ie_user_location_information("001/01", 0x123456789, "000001")
    check("uli-octets", uli.hex() == "0079000f4000f110123456789000f110000001", uli.hex())
    check("uli-choice-is-two-bits", uli.hex()[8:10] == "40",
          "a location report whose CHOICE and two preambles do not share the "
          "first octet opens 20 or spends an extra one")
    check("uli-nci-36-bits", "1234567890" in uli.hex(), uli.hex())
    check("uli-tac-three-octets", uli.hex().endswith("00f110000001"), uli.hex())
    for bad_tac in ("0001", "00000001"):
        try:
            ie_user_location_information("001/01", 1, bad_tac)
            ok = False
        except ValueError:
            ok = True
        check("uli-rejects-%d-octet-tac" % (len(bad_tac) // 2), ok)
    try:
        ie_user_location_information("001/01", 1 << 36, "000001")
        ok = False
    except ValueError:
        ok = True
    check("uli-rejects-37-bit-cell", ok)

    cause = ie_rrc_establishment_cause("mo-Data")
    check("cause-mo-data", cause.hex() == "005a400120", cause.hex())
    check("cause-mo-signalling", ie_rrc_establishment_cause("mo-Signalling").hex()
          == "005a400118", ie_rrc_establishment_cause("mo-Signalling").hex())
    check("cause-emergency", ie_rrc_establishment_cause("emergency").hex()
          == "005a400100", ie_rrc_establishment_cause("emergency").hex())
    check("cause-criticality-is-ignore", cause.hex()[4:6] == "40", cause.hex())
    try:
        ie_rrc_establishment_cause("because-i-said-so")
        ok = False
    except ValueError:
        ok = True
    check("cause-rejects-unknown", ok)

    node = ie_global_ran_node_id("001/01", 0x0A1C01)
    check("global-ran-node", node.hex() == "001b00080000f11000287004", node.hex())
    wide = ie_global_ran_node_id("001/01", 0xFFFFFFFF, 32)
    check("gnb-id-length-is-four-bits", wide.hex()[16:18] == "50", wide.hex())
    check("gnb-id-32-bits-carried", wide.hex().endswith("ffffffff"), wide.hex())
    try:
        ie_global_ran_node_id("001/01", 1, 21)
        ok = False
    except ValueError:
        ok = True
    check("gnb-id-rejects-21-bits", ok)

    name = ie_ran_node_name("LabGnb")
    check("ran-node-name", name.hex() == "0052400802804c6162476e62", name.hex())
    check("ran-node-name-length-first-bit", name.hex()[8:10] == "02",
          "an extensible size constraint opens 02 80 for six characters, not 05 00")
    check("ran-node-name-one-char", ie_ran_node_name("A").hex() == "00524003000041",
          ie_ran_node_name("A").hex())
    try:
        ie_ran_node_name("")
        ok = False
    except ValueError:
        ok = True
    check("ran-node-name-rejects-empty", ok)

    slice_list = _slice_support_list(1)
    check("slice-support-item", slice_list.hex() == "00000008", slice_list.hex())
    check("slice-sst-is-not-aligned", slice_list.hex()[4:] == "0008",
          "an SST written as an octet aligns first and the item becomes three octets")
    try:
        _slice_support_list(0x100)
        ok = False
    except ValueError:
        ok = True
    check("slice-rejects-two-octet-sst", ok)

    setup_rows = dict(decode(bytes.fromhex(by_name["ng-setup-full"])))
    check("decode-ng-setup-procedure", setup_rows.get("procedure") == "NGSetupRequest",
          str(setup_rows.get("procedure")))
    setup_blob = " ".join(v for k, v in decode(bytes.fromhex(by_name["ng-setup-full"]))
                          if k == "ie")
    check("decode-ng-setup-name", "LabGnb" in setup_blob, setup_blob)
    check("decode-ng-setup-tac", "tac 000001" in setup_blob, setup_blob)
    check("decode-ng-setup-slice", "sst 01" in setup_blob, setup_blob)
    check("decode-ng-setup-no-undecodable", "undecodable" not in setup_blob, setup_blob)

    located_blob = " ".join(v for k, v in decode(bytes.fromhex(by_name["initial-ue-located"]))
                            if k == "ie")
    check("decode-location-cell", "nrcgi 001/01 123456789" in located_blob, located_blob)
    check("decode-location-cause", "mo-Data" in located_blob, located_blob)
    check("decode-location-no-undecodable", "undecodable" not in located_blob, located_blob)

    print("ASSERTIONS\t%d" % (passed + failed))
    print("RESULT\t%s" % ("PASS" if failed == 0 else "FAIL"))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
