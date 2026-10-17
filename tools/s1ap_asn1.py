#!/usr/bin/env python3
"""
S1AP over APER -- TS 36.413 message bodies, encoded to real octets.

Why this exists and why it is not part of tools/lte_asn1.py: LTE RRC is
unaligned PER (X.691 "basic" alignment, no padding between fields), and S1AP
is *aligned* PER (X.691 "canonical" alignment, every field padded to an octet
boundary where the type says so).  The two share a vocabulary and nothing
else.  Feeding an S1AP body to the RRC codec produces plausible-looking
garbage, which is the trap this file is written to avoid.

What is verified and how.  A vector ships only if pycrate 0.8.1
(pycrate_asn1dir.S1AP), an independent implementation of the same ASN.1, reads
the bytes back as the structure this file claims to have written.  pycrate is
not a dependency of this tree, so the check ran once, off-tree, and the
conclusion is recorded next to the vector.

IE status, and it is not uniform -- this file is deliberately half-finished
rather than uniformly plausible:

  Global-ENB-ID       VERIFIED    pycrate decodes pLMNidentity and the 20-bit
                                  macro eNB id from our octets.
  Criticality         VERIFIED    extensible ENUMERATED: the octet is
                                  0bEII00000, so ignore is 0x40 and not 0x01.
  PagingDRX           VERIFIED    same shape, index in bits 6-7.
  ENBname             VERIFIED    two pieces, both of which this file had
                                  wrong: the size constraint is extensible so
                                  one extension bit comes first, and the
                                  length is (n-1) and not n.  Nine bits,
                                  padded, so a 7-character name opens 03 00.
  SupportedTAs        VERIFIED    count is (n-1) in eight bits because the
                                  size constraint is 1..256; the item's two
                                  preamble bits are NOT padded before the
                                  TAC, and the PLMN count is (n-1) in three
                                  bits, all one padded run, then the PLMNs.

Second referee.  pycrate and Wireshark are independent dissectors, so every
vector was replayed through tshark 4.2.2 as an SCTP DATA chunk with PPID 18
and dissected from scratch.  tshark reading back id-S1Setup, procedureCode 17,
MCC 001 / MNC 01, macroENB-ID 0xA1C01 at 20 bits with 4 pad bits, ENBname
LabHeNB, tAC 241 and PLMN 00f110 with no Malformed verdict is what moved each
IE from UNRESOLVED to VERIFIED above.

NOT VERIFIED, and deliberately not wired: InitialUEMessage,
DownlinkNASTransport and Paging.  tshark reads their identity IEs back as zero,
so the INTEGER encodings for MME-UE-S1AP-ID and ENB-UE-S1AP-ID are still
wrong and the paging UE-Identity IE id is still wrong.  The three verbs print
status unverified and exit 3 rather than hand a caller bytes that a real MME
would discard.

Usage:
    s1ap_asn1.py s1setup --mcc 001 --mnc 01 --enb-id 0xA1C01 \
                         --name LabHeNB --tac 00f1 [--pdrx v64]
    s1ap_asn1.py initial-ue --mme-ue-id 1 --enb-ue-id 7 --nas <hex>
    s1ap_asn1.py downlink-nas --mme-ue-id 1 --enb-ue-id 7 --nas <hex>
    s1ap_asn1.py paging --ue-id-msin <bcd-hex> --tac 00f1
    s1ap_asn1.py decode <hex>
    s1ap_asn1.py selftest

Output is KEY<TAB>value, one key per line, the same contract every other tool
in this tree keeps.
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# TS 36.413 clause 9.2 -- IE ids this file emits.
# ---------------------------------------------------------------------------
IE_GLOBAL_ENB_ID = 59
IE_ENBNAME = 60
IE_SUPPORTED_TAS = 64
IE_DEFAULT_PAGING_DRX = 137
IE_MME_UE_S1AP_ID = 0
IE_ENB_UE_S1AP_ID = 8
IE_NAS_PDU = 26
IE_UE_IDENTITY_PAGING = 115
IE_CNDOMAIN = 109

PROC_S1_SETUP = 17
PROC_INITIAL_UE = 12
PROC_DOWNLINK_NAS = 11
PROC_PAGING = 10

# Criticality is ENUMERATED { reject, ignore, notify } with an extension
# marker, so the octet is 0bEII00000: the extension flag in the top bit and the
# index in the two below it.  Writing the bare index 0/1/2 instead produces a
# body that a decoder reads as an extension marker and then loses sync on --
# which is exactly how the first draft of this file failed.
CRITICALITY = {"reject": 0x00, "ignore": 0x40, "notify": 0x80}
CRITICALITY_NAME = {v: k for k, v in CRITICALITY.items()}

# PagingDRX is ENUMERATED { v32, v64, v128, v256, ... }: extension flag, then
# the index in the next two bits.
PAGING_DRX = {"v32": 0x00, "v64": 0x20, "v128": 0x40, "v256": 0x60}
PAGING_DRX_NAME = {v: k for k, v in PAGING_DRX.items()}


class AperWriter:
    """Aligned-PER writer, bits first, octets out.

    Alignment is explicit rather than automatic: in aligned PER an octet
    alignment happens where the type says it happens, not wherever a field
    ends, so a writer that pads on its own gets the length of a BIT STRING
    wrong by four bits and nothing else complains.
    """

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

    def octet(self, value):
        assert 0 <= value <= 0xFF, "octet out of range: %r" % (value,)
        self.align()
        self.bits(value, 8)
        return self

    def octets(self, data):
        for byte in data:
            self.octet(byte)
        return self

    def length_determinant(self, count):
        """Aligned-PER length determinant for a value under 128, one octet.

        S1AP's containers are all SIZE(0..65535) or SIZE(1..max), and those
        use a constrained count from the size constraint instead of this --
        see constrained_count().  This exists for the open type, whose length
        is an ordinary determinant.
        """
        if count >= 128:
            raise ValueError("open type over 127 octets needs the long form")
        return self.octet(count)

    def constrained_count(self, count, upper_bits):
        """Count from a size constraint, in the minimum whole bits, aligned."""
        self.align()
        self.bits(count, upper_bits)
        return self.align()

    def taked(self):
        self.align()
        out = bytearray()
        for i in range(0, len(self._bits), 8):
            byte = 0
            for bit in self._bits[i:i + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


class AperReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self._bits = []
        for byte in data:
            for shift in range(7, -1, -1):
                self._bits.append((byte >> shift) & 1)
        self.bitpos = 0

    def bit(self):
        if self.bitpos >= len(self._bits):
            raise ValueError("ran off the end at bit %d" % self.bitpos)
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

    def octet(self):
        self.align()
        if self.bitpos + 8 > len(self._bits):
            raise ValueError("ran off the end at byte %d" % (self.bitpos // 8))
        value = self.bits(8)
        self.pos = self.bitpos // 8
        return value

    def octets(self, count):
        return bytes(self.octet() for _ in range(count))

    def remaining(self):
        return (len(self._bits) - self.bitpos) // 8


# ---------------------------------------------------------------------------
# Container helpers -- the message body.
# ---------------------------------------------------------------------------

def _criticality_octet(name):
    if name not in CRITICALITY:
        raise ValueError("criticality must be one of %s" % ", ".join(CRITICALITY))
    return CRITICALITY[name]


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
    """ProtocolIE-Container: an extensible SEQUENCE holding a 16-bit count.

    The preamble is one extension bit for the SEQUENCE's own `...`, padded to
    an octet; the count comes from SIZE(0..65535), so it is 16 bits wide and
    not a length determinant.  Getting that wrong is the single most common
    way an S1AP body decodes as "the IE list is empty, trailing bytes
    ignored" -- which reads like success and is not.
    """
    writer = AperWriter()
    writer.bit(0)                       # no extension additions present
    writer.align()
    writer.constrained_count(len(ie_fields), 16)
    for field in ie_fields:
        writer.octets(field)
    return writer.taked()


# ---------------------------------------------------------------------------
# Individual IEs -- TS 36.413 clause 9.2.x.
# ---------------------------------------------------------------------------

def _plmn(mcc, mnc):
    """PLMNidentity: three octets, MCC2|MCC1, MNC3|MCC3, MNC2|MNC1.

    A two-digit MNC pads the third nibble with 0xF (TS 24.008 10.5.1.3).  This
    is the third copy of that rule in the tree; it is written here to the
    clause and asserted in the selftest against the value the MNC digitiser
    produces for 310/260, which the other two copies already agree on.
    """
    mcc = str(mcc).zfill(3)
    mnc = str(mnc).zfill(2) if len(str(mnc)) == 2 else str(mnc).zfill(3)
    if len(mcc) != 3:
        raise ValueError("MCC must be three digits")
    if len(mnc) not in (2, 3):
        raise ValueError("MNC must be two or three digits")
    mnc3 = mnc[2] if len(mnc) == 3 else "f"
    digits = "%s%s%s%s%s%s" % (mcc[1], mcc[0], mnc3, mcc[2], mnc[1], mnc[0])
    return bytes.fromhex(digits)


def ie_global_enb_id(mcc, mnc, enb_id, width=20):
    """Global-ENB-ID: SEQUENCE { pLMNidentity, eNB-ID }, extensible.

    The preamble is the extension bit plus the bit for the OPTIONAL
    iE-Extensions (absent), so one octet of zeros.  eNB-ID is a CHOICE whose
    index is a normally-small number: the extension flag lives in the top bit
    of that octet, so a root index of 0 is the octet 0x00.
    """
    if width not in (20, 28):
        raise ValueError("eNB id width must be 20 (macro) or 28 (home)")
    if enb_id < 0 or enb_id >= (1 << width):
        raise ValueError("eNB id does not fit in %d bits" % width)
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bit(0)                       # no iE-Extensions
    writer.align()
    writer.octets(_plmn(mcc, mnc))
    writer.octet(0 if width == 20 else 1)   # eNB-ID CHOICE, not extended
    writer.bits(enb_id, width)
    writer.align()
    return _ie_field(IE_GLOBAL_ENB_ID, "reject", writer.taked())


def ie_enbname(name):
    """ENBname: PrintableString (SIZE(1..150, ...)).

    Two things both reference decoders insisted on and this file had wrong.
    The size constraint is extensible, so one extension bit comes first.  The
    length itself is the value minus the lower bound -- (n-1), not n -- in the
    eight bits the range 1..150 needs.  Together that is a nine-bit run padded
    to an octet, so a seven-character name opens with 03 00 and not 07.
    """
    data = name.encode("ascii")
    if not 1 <= len(data) <= 150:
        raise ValueError("eNB name must be 1..150 printable characters")
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bits(len(data) - 1, 8)       # length minus the lower bound
    writer.align()
    writer.octets(data)
    return _ie_field(IE_ENBNAME, "ignore", writer.taked())


def ie_supported_tas(plmns, tacs):
    """SupportedTAs: SEQUENCE(SIZE(1..256)) OF SupportedTA-Item.

    Each item is { tAC OCTET STRING(SIZE(2)), broadcastPLMNs
    SEQUENCE(SIZE(1..6)) OF PLMNidentity }; both counts are constrained, so
    the TAC count is 8 bits and the PLMN count 4 bits (SIZE 1..6), aligned.
    """
    if not 1 <= len(tacs) <= 256:
        raise ValueError("SupportedTAs needs 1..256 tracking areas")
    if not 1 <= len(plmns) <= 6:
        raise ValueError("each TAC broadcasts 1..6 PLMNs")
    writer = AperWriter()
    # SIZE(1..256) is not extensible, so no flag: just the count minus the
    # lower bound, eight bits, padded to an octet.
    writer.bits(len(tacs) - 1, 8)
    writer.align()
    for tac in tacs:
        raw = bytes.fromhex(str(tac))
        if len(raw) != 2:
            raise ValueError("a TAC is two octets, got %r" % (tac,))
        # SupportedTAs-Item is extensible with one OPTIONAL iE-Extensions, so
        # its preamble is two bits, and those two bits are NOT padded before
        # the TAC: preamble, TAC and the PLMN count run together and are
        # padded as one run.  Padding after the preamble would be the obvious
        # reading and both reference decoders reject it.
        writer.bit(0)                   # no extension additions
        writer.bit(0)                   # no iE-Extensions
        writer.bits(int.from_bytes(raw, "big"), 16)
        writer.bits(len(plmns) - 1, 3)  # SIZE(1..6), minus the lower bound
        writer.align()
        for mcc, mnc in plmns:
            writer.octets(_plmn(mcc, mnc))
    return _ie_field(IE_SUPPORTED_TAS, "reject", writer.taked())


def ie_default_paging_drx(drx):
    """DefaultPagingDRX: ENUMERATED { v32, v64, v128, v256, ... }, extensible."""
    drx = drx.lower()
    if drx not in PAGING_DRX:
        raise ValueError("paging DRX must be one of %s" % ", ".join(PAGING_DRX))
    writer = AperWriter()
    writer.octet(PAGING_DRX[drx])
    return _ie_field(IE_DEFAULT_PAGING_DRX, "reject", writer.taked())


def ie_mme_ue_s1ap_id(value):
    """MME-UE-S1AP-ID: INTEGER (0..4294967295), four octets, aligned."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("MME-UE-S1AP-ID is a 32-bit unsigned integer")
    writer = AperWriter()
    writer.bits(value, 32)
    writer.align()
    return _ie_field(IE_MME_UE_S1AP_ID, "reject", writer.taked())


def ie_enb_ue_s1ap_id(value):
    """ENB-UE-S1AP-ID: INTEGER (0..16777215), three octets, aligned."""
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("ENB-UE-S1AP-ID is a 24-bit unsigned integer")
    writer = AperWriter()
    writer.bits(value, 24)
    writer.align()
    return _ie_field(IE_ENB_UE_S1AP_ID, "reject", writer.taked())


def ie_nas_pdu(nas):
    """NAS-PDU: OCTET STRING, a length determinant then the bytes."""
    writer = AperWriter()
    writer.length_determinant(len(nas))
    writer.octets(nas)
    return _ie_field(IE_NAS_PDU, "reject", writer.taked())


def ie_cn_domain(domain="ps"):
    """CN-Domain: ENUMERATED { ps, cs, ... }, extensible."""
    writer = AperWriter()
    writer.octet(0x00 if domain.lower() == "ps" else 0x40)
    return _ie_field(IE_CNDOMAIN, "ignore", writer.taked())


def ie_ue_identity_paging(msin_bcd):
    """UE-Identity: CHOICE { s-TMSI, iMSI, ... }; iMSI is a fixed 8 octets.

    The index is a normally-small number, so iMSI (root index 1) is the octet
    0x01.  The BCD is the same nibble-swapped form the rest of the tree uses.
    """
    raw = bytes.fromhex(str(msin_bcd))
    if len(raw) != 8:
        raise ValueError("a paging IMSI is exactly eight octets")
    writer = AperWriter()
    writer.octet(0x40)                  # iMSI: extension flag 0, root index 1
    writer.octets(raw)
    return _ie_field(IE_UE_IDENTITY_PAGING, "reject", writer.taked())


# ---------------------------------------------------------------------------
# PDUs -- the S1AP-PDU envelope, TS 36.413 clause 9.1.
# ---------------------------------------------------------------------------

def _pdu(procedure_code, criticality, body):
    """S1AP-PDU: CHOICE { initiatingMessage, ... } then InitiatingMessage.

    The CHOICE index is 0 for an initiating message and the extension flag is
    the top bit of that same octet, so the whole discriminator is 0x00.
    InitiatingMessage is a plain SEQUENCE with no extension marker and no
    optionals, so it has no preamble at all: procedureCode, criticality, then
    the body as an open type.
    """
    writer = AperWriter()
    writer.octet(0)
    writer.octet(procedure_code)
    writer.octet(_criticality_octet(criticality))
    _open_type(writer, body)
    return writer.taked()


def s1setup_request(mcc, mnc, enb_id, name, tacs, plmns=None, drx="v64"):
    plmns = plmns or [(mcc, mnc)]
    fields = [
        ie_global_enb_id(mcc, mnc, enb_id),
        ie_enbname(name),
        ie_supported_tas(plmns, tacs),
        ie_default_paging_drx(drx),
    ]
    return _pdu(PROC_S1_SETUP, "reject", _container(fields))


def initial_ue_message(mme_ue_id, enb_ue_id, nas, tac):
    fields = [
        ie_enb_ue_s1ap_id(enb_ue_id),
        ie_mme_ue_s1ap_id(mme_ue_id),
        ie_nas_pdu(nas),
        ie_supported_tas([("001", "01")], [tac]),
        ie_cn_domain("ps"),
    ]
    return _pdu(PROC_INITIAL_UE, "reject", _container(fields))


def downlink_nas_transport(mme_ue_id, enb_ue_id, nas):
    fields = [
        ie_mme_ue_s1ap_id(mme_ue_id),
        ie_enb_ue_s1ap_id(enb_ue_id),
        ie_nas_pdu(nas),
    ]
    return _pdu(PROC_DOWNLINK_NAS, "reject", _container(fields))


def paging(msin_bcd, tac):
    fields = [
        ie_ue_identity_paging(msin_bcd),
        ie_supported_tas([("001", "01")], [tac]),
    ]
    return _pdu(PROC_PAGING, "ignore", _container(fields))


# ---------------------------------------------------------------------------
# Decoder -- enough of the envelope and the IEs above to read back what this
# file writes, and to name an IE it does not know instead of guessing.
# ---------------------------------------------------------------------------

IE_NAMES = {
    IE_MME_UE_S1AP_ID: "MME-UE-S1AP-ID",
    IE_ENB_UE_S1AP_ID: "ENB-UE-S1AP-ID",
    IE_NAS_PDU: "NAS-PDU",
    IE_GLOBAL_ENB_ID: "Global-ENB-ID",
    IE_ENBNAME: "eNBname",
    IE_SUPPORTED_TAS: "SupportedTAs",
    IE_CNDOMAIN: "CN-Domain",
    IE_UE_IDENTITY_PAGING: "UE-Identity",
    IE_DEFAULT_PAGING_DRX: "DefaultPagingDRX",
}

PROCEDURE_NAMES = {
    PROC_PAGING: "Paging",
    PROC_DOWNLINK_NAS: "DownlinkNASTransport",
    PROC_INITIAL_UE: "InitialUEMessage",
    PROC_S1_SETUP: "S1Setup",
}


def _plmn_text(raw):
    if len(raw) != 3:
        return raw.hex()
    a, b, c = raw
    mcc = "%d%d%d" % (a & 0x0F, a >> 4, b & 0x0F)
    mnc = "%d%d" % (c & 0x0F, c >> 4)
    if (b >> 4) != 0x0F:
        mnc = "%d%d" % (c & 0x0F, c >> 4) if False else "%d%s%d" % (c & 0x0F, "%x" % (b >> 4) if (b >> 4) != 0xF else "", c >> 4)
    return "%s/%s" % (mcc, mnc.upper())


def _decode_ie(reader, ie_id):
    """Read one IE's body from an open type we have just framed."""
    if ie_id == IE_MME_UE_S1AP_ID:
        return str(reader.bits(32) or 0), reader
    if ie_id == IE_ENB_UE_S1AP_ID:
        return str(reader.bits(24)), reader
    if ie_id == IE_NAS_PDU:
        count = reader.octet()
        return reader.octets(count).hex(), reader
    if ie_id == IE_GLOBAL_ENB_ID:
        reader.bit()                    # extension
        reader.bit()                    # iE-Extensions present?
        reader.align()
        plmn = _plmn_text(reader.octets(3))
        alt = reader.octet() >> 6
        width = 20 if alt == 0 else 28
        enb = reader.bits(width)
        reader.align()
        return "%s enb=%#x" % (plmn, enb), reader
    if ie_id == IE_ENBNAME:
        reader.bit()                        # extension flag
        count = reader.bits(8) + 1          # length minus the lower bound
        reader.align()
        return reader.octets(count).decode("ascii", "replace"), reader
    if ie_id == IE_SUPPORTED_TAS:
        count = reader.bits(8) + 1
        reader.align()
        parts = []
        for _ in range(count):
            reader.bit()                    # the item's extension flag
            reader.bit()                    # iE-Extensions present?
            tac = reader.bits(16)
            nplmn = reader.bits(3) + 1      # size 1..6, minus the lower bound
            reader.align()
            plmns = [_plmn_text(reader.octets(3)) for _ in range(nplmn)]
            parts.append("%04x[%s]" % (tac, ",".join(plmns)))
        return " ".join(parts), reader
    if ie_id == IE_CNDOMAIN:
        return ("ps" if reader.octet() == 0x00 else "cs"), reader
    if ie_id == IE_DEFAULT_PAGING_DRX:
        index = reader.octet()
        return PAGING_DRX_NAME.get(index, "index %d" % index), reader
    if ie_id == IE_UE_IDENTITY_PAGING:
        alt = reader.octet() >> 6
        if alt == 0:                    # s-TMSI: 4 octets
            return "s-tmsi " + reader.octets(4).hex(), reader
        return "imsi " + reader.octets(8).hex(), reader
    raise ValueError("no decoder for IE id %d" % ie_id)


def decode(raw):
    """Return a list of (key, value) rows for one S1AP-PDU."""
    if len(raw) < 4:
        raise ValueError("too short to be an S1AP-PDU")
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
    inner.bit()                         # the body SEQUENCE's extension bit
    inner.align()
    count = inner.bits(16)
    inner.align()
    rows.append(("ies", "%d" % count))
    for index in range(count):
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
    print("pdu\tS1AP")
    print("octets\t%d" % (len(hexbody) // 2))
    print("hex\t%s" % hexbody)


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("s1setup", help="S1SetupRequest")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--enb-id", required=True, type=lambda v: int(v, 0))
    p.add_argument("--name", default="LabHeNB")
    p.add_argument("--tac", action="append", required=True)
    p.add_argument("--pdrx", default="v64")

    p = sub.add_parser("initial-ue", help="InitialUEMessage")
    p.add_argument("--mme-ue-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--enb-ue-id", type=lambda v: int(v, 0), default=7)
    p.add_argument("--nas", required=True)
    p.add_argument("--tac", required=True)

    p = sub.add_parser("downlink-nas", help="DownlinkNASTransport")
    p.add_argument("--mme-ue-id", type=lambda v: int(v, 0), default=1)
    p.add_argument("--enb-ue-id", type=lambda v: int(v, 0), default=7)
    p.add_argument("--nas", required=True)

    p = sub.add_parser("paging", help="Paging")
    p.add_argument("--ue-id-msin", required=True)
    p.add_argument("--tac", required=True)

    p = sub.add_parser("decode", help="decode one S1AP-PDU from hex")
    p.add_argument("hex")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)
    try:
        if args.verb == "s1setup":
            _emit(s1setup_request(args.mcc, args.mnc, args.enb_id, args.name,
                                  args.tac, drx=args.pdrx).hex())
        elif args.verb in ("initial-ue", "downlink-nas", "paging"):
            # Not one of these three survives a real dissector yet, and an MME
            # silently drops a message whose IE it cannot read.  Refusing is
            # the only honest answer until the INTEGER and UE-Identity
            # encodings are pinned the way S1Setup has been.
            print("status\tunverified")
            print("reason\tidentity IE encoding is not yet agreed with pycrate"
                  " and tshark; see the IE status table in this file")
            print("verb\t%s" % args.verb)
            return 3
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
# Vectors.  Each hex below was encoded here and then read back by pycrate
# 0.8.1 before it was written down; the structure pycrate printed is in the
# comment.  A vector that pycrate could not read did not go in this table.
# ---------------------------------------------------------------------------

VECTORS = [
    # id 59 alone: pycrate and tshark both read pLMNidentity 00F110 and
    # macroENB-ID A1C01 from these octets.
    ("global-enb-id",
     "003b00080000f11000a1c010",
     "Global-ENB-ID, macro, PLMN 001/01, eNB 0xA1C01"),
    # A seven-character name; the 03 00 opener is the finding.
    ("enbname-labhenb",
     "003c400903004c616248654e42",
     "ENBname LabHeNB"),
    # One TAC, one PLMN; 00 3C 40 is preamble + TAC + PLMN count as one run.
    ("supported-tas-one",
     "0040000700003c4000f110",
     "SupportedTAs 00f1 [001/01]"),
    # Two PLMNs on the same TAC: same run, one more octet of count.
    ("supported-tas-two-plmn",
     "0040000a00003c4800f11000f120",
     "SupportedTAs 00f1 [001/01 001/02]"),
    ("paging-drx-v64", "0089000120", "DefaultPagingDRX v64"),
    # The whole message, dissected by tshark as four items with values.
    ("s1setup-full",
     "0011002c000004003b00080000f11000a1c010003c400903004c616248654e42"
     "0040000700003c4000f1100089000120",
     "s1setup 001 01 0xA1C01 LabHeNB 00f1"),
]


def selftest():
    """Encode what we can, then read it back with our own decoder.

    The decoder is not an independent check of the encoder -- they are two
    halves of one file, and a bit error mirrored in both passes.  The
    independent half is tools/s1ap-oracle/, produced by pycrate; it pins the
    byte strings, and this pins that both halves still move together.
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

    # The PLMN the other two copies in this tree agree on: 310/260 is 130062.
    check("plmn-310-260", _plmn(310, 260).hex() == "130062", _plmn(310, 260).hex())
    check("plmn-001-01", _plmn("001", "01").hex() == "00f110", _plmn("001", "01").hex())

    # Criticality is the trap: the bare index decodes as an extension
    # marker and the body loses sync a field later.
    check("criticality-reject-00", _criticality_octet("reject") == 0x00)
    check("criticality-ignore-40", _criticality_octet("ignore") == 0x40)
    check("criticality-notify-80", _criticality_octet("notify") == 0x80)
    check("pagingdrx-v64-20", PAGING_DRX["v64"] == 0x20)

    # Each encoder must reproduce the bytes both referees accepted, exactly.
    check("encode-global-enb-id",
          ie_global_enb_id("001", "01", 0xA1C01).hex() == VECTORS[0][1])
    check("encode-enbname", ie_enbname("LabHeNB").hex() == VECTORS[1][1])
    check("encode-supported-tas",
          ie_supported_tas([("001", "01")], ["00f1"]).hex() == VECTORS[2][1])
    check("encode-supported-tas-two",
          ie_supported_tas([("001", "01"), ("001", "02")], ["00f1"]).hex()
          == VECTORS[3][1])
    check("encode-paging-drx",
          ie_default_paging_drx("v64").hex() == VECTORS[4][1])
    check("encode-s1setup-full",
          s1setup_request("001", "01", 0xA1C01, "LabHeNB", ["00f1"]).hex()
          == VECTORS[5][1])

    # decode() returns one row per IE and the key repeats, so this walks the
    # list and not a dict -- collapsing it was hiding three of four IEs.
    allrows = decode(bytes.fromhex(VECTORS[5][1]))
    first = dict(allrows)
    check("decode-full-procedure", first.get("procedure") == "S1Setup", str(first))
    check("decode-full-four-ies", first.get("ies") == "4", first.get("ies", ""))
    joined = " ".join(v for k, v in allrows if k == "ie")
    check("decode-full-names", "LabHeNB" in joined, joined)
    check("decode-full-plmn", "001/01" in joined, joined)
    check("decode-full-no-undecodable", "undecodable" not in joined, joined)

    # The two-octet count is the detail that fails silently: a one-octet
    # count still parses, and reports an empty IE list.
    body = _container([ie_enbname("X")])
    check("container-count-is-16-bit", body[1:3] == b"\x00\x01", body[:4].hex())

    # Alignment: a 20-bit BIT STRING inside Global-ENB-ID must pad to a whole
    # octet, so the IE body is 1 preamble + 3 PLMN + 1 choice + 3 bits = 8.
    ie = ie_global_enb_id("001", "01", 0xA1C01)
    check("global-enb-id-body-8", len(ie) == 2 + 1 + 1 + 8, str(len(ie)))

    print("ASSERTIONS\t%d" % (passed + failed))
    print("RESULT\t%s" % ("PASS" if failed == 0 else "FAIL"))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
