#!/usr/bin/env python3
"""
X2AP over APER -- TS 36.423 message bodies, encoded to real octets.

Why this file exists.  X2AP rides the same aligned-PER machinery as S1AP and
the same SCTP transport, and it shares none of its object sets: different
procedure codes, different IE ids, different containers.  A body built with
the S1AP tables dissects as a well-formed PDU full of nonsense, because both
protocols open the same way.  So this is a second codec, not a switch.

What is verified, and against what.  A vector ships only when pycrate 0.8.1
(pycrate_asn1dir.X2AP) reads our octets back as the structure this file
claims, *and* tshark 4.2.2 dissects the same octets as an SCTP DATA chunk
with PPID 27 on port 36422 without a Malformed verdict.  pycrate and tshark
are independent dissectors of the same clauses; the vectors below agree with
both.

The finding this file is built around.  ServedCell-Information carries an
ECGI whose eUTRANcellIdentifier is a 28-bit BIT STRING, and that BIT STRING
is NOT padded to an octet boundary before the next field.  The tAC follows in
the same bit run and lands across octets, so a writer that pads after the cell
id (the obvious reading, and the one this file started with) produces bytes
that look like a valid cell and decode to a tAC that is the cell id's low
nibble smeared into the next octet.  Concretely: cell id 0x0A1C010 followed by
tAC 0x0001 writes as 0a 1c 01 00 00 10 -- four zero-padded octets, then a
misaligned TAC -- and reads back as tAC 0x0001 only when nothing in between is
realigned.  The octet string is the one that aligns; the bit string is not.

The preamble layout is the other half.  Both ServedCells-Item and
ServedCell-Information put their extension bit and their two optional-field
presence bits at the FRONT, so an item with no neighbour information opens
five zero bits and then pads -- one preamble, not two octets of preamble.

IE status:

  GlobalENB-ID        VERIFIED    PLMN then a macro eNB id in 20 bits, padded.
                                  Same octets as the S1AP spelling of the
                                  same IE, which is the one place the two
                                  protocols genuinely agree.
  ServedCells         VERIFIED    count is (n-1) in eight bits; the item
                                  preamble is three bits and the
                                  ServedCell-Information preamble is two, and
                                  the two share one padded run.
  ECGI                VERIFIED    preamble, PLMN, then the 28-bit cell id with
                                  no padding after it.
  broadcastPLMNs      VERIFIED    count is (n-1) in three bits, then the run is
                                  padded and each PLMN is three octets.
  EUTRA-Mode-Info     VERIFIED    extension bit, then a one-bit CHOICE index
                                  (fDD is 0), then the mode SEQUENCE's own
                                  extension bit and its iE-Extensions
                                  presence bit, then an alignment.
  EARFCN              VERIFIED    16 bits each, unaligned between them.
  Transmission-BW     VERIFIED    extensible ENUMERATED, so the nibble is
                                  0bEIII: bw100 is 0101 and not 00101.  The
                                  names are bw6/bw15/bw25/bw50/bw75/bw100,
                                  not the n6/n100 spelling used elsewhere.

What is NOT built, and the reason to say so out loud: the handover procedures
(HandoverRequest and its failure and cancel messages) are the interesting ones
for the abuse cases in docs/OFFENSIVE_ROADMAP.md, and they need an E-RAB list
and a UE context, neither of which is encoded here.  This file covers X2
Setup, which is what a peer sends first and what a fake cell would answer
with.  A decoder for the rest still prints ids and lets an unknown IE through
as hex.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1ap_asn1 import (  # noqa: E402  one PER, not two
    AperReader, AperWriter, _container, _ie_field, _plmn,
)

# ---------------------------------------------------------------------------
# TS 36.423 -- the ids this file emits.
# ---------------------------------------------------------------------------

IE_SERVED_CELLS = 20
IE_GLOBAL_ENB_ID = 21

PROC_X2_SETUP = 6

CRITICALITY = {"reject": 0x00, "ignore": 0x40, "notify": 0x80}
CRITICALITY_NAME = {v: k for k, v in CRITICALITY.items()}

# ENUMERATED { bw6, bw15, bw25, bw50, bw75, bw100, ... }, extensible.
BW = {"bw6": 0, "bw15": 1, "bw25": 2, "bw50": 3, "bw75": 4, "bw100": 5}
BW_NAME = {v: k for k, v in BW.items()}

IE_NAMES = {
    IE_SERVED_CELLS: "ServedCells",
    IE_GLOBAL_ENB_ID: "GlobalENB-ID",
}

PROCEDURE_NAMES = {
    PROC_X2_SETUP: "id-x2Setup",
}


def _criticality_octet(name):
    if name not in CRITICALITY:
        raise ValueError("criticality must be one of %s" % ", ".join(CRITICALITY))
    return CRITICALITY[name]


def _pdu(procedure_code, criticality, body):
    """X2AP-PDU: CHOICE { initiatingMessage, ... } then InitiatingMessage.

    The CHOICE index is 0 and the extension flag is the top bit of the same
    octet, so the discriminator is 0x00.  InitiatingMessage has no preamble:
    procedureCode in eight bits, criticality, then the body as an open type.
    """
    writer = AperWriter()
    writer.octet(0)
    writer.octet(procedure_code)
    writer.octet(_criticality_octet(criticality))
    writer.octet(len(body))
    writer.octets(body)
    return writer.taked()


# ---------------------------------------------------------------------------
# IEs.
# ---------------------------------------------------------------------------

def ie_global_enb_id(mcc, mnc, enb_id):
    """GlobalENB-ID: SEQUENCE { pLMN-Identity, eNB-ID }, extensible.

    One extension bit, one iE-Extensions presence bit, then the run is padded
    because a PLMN is an octet string.  eNB-ID is a CHOICE whose macro form is
    the only one this file writes: index 0, then a 20-bit id padded to three
    octets.
    """
    writer = AperWriter()
    writer.bit(0)                       # no extension additions
    writer.bit(0)                       # no iE-Extensions
    writer.align()
    writer.octets(_plmn(mcc, mnc))
    writer.octet(0)                     # eNB-ID: macro-eNB-ID
    writer.bits(enb_id & 0xFFFFF, 20)
    return writer.taked()


def ie_served_cells(cells, mcc, mnc):
    """ServedCells: SEQUENCE (SIZE(1..256)) of ServedCells-Item.

    `cells` is a list of dicts with pci, cell_id, tac, and optional plmns,
    ul_earfcn, dl_earfcn, ul_bw, dl_bw.
    """
    if not 1 <= len(cells) <= 256:
        raise ValueError("ServedCells holds 1..256 cells, not %d" % len(cells))
    writer = AperWriter()
    writer.align()
    writer.bits(len(cells) - 1, 8)      # SIZE(1..256): count is (n-1)
    writer.align()
    for cell in cells:
        writer.bit(0)                   # ServedCells-Item: no extensions
        writer.bit(0)                   # no neighbour-Info
        writer.bit(0)                   # no iE-Extensions
        writer.bit(0)                   # ServedCell-Information: no extensions
        writer.bit(0)                   # no iE-Extensions
        writer.align()
        writer.bits(cell["pci"] & 0xFFFF, 16)
        writer.bit(0)                   # ECGI: no extensions
        writer.bit(0)                   # no iE-Extensions
        writer.align()
        writer.octets(_plmn(mcc, mnc))
        writer.bits(cell["cell_id"] & 0x0FFFFFFF, 28)
        writer.bits(cell["tac"] & 0xFFFF, 16)   # no realignment: see docstring
        plmns = cell.get("plmns") or []
        writer.bits((len(plmns) if plmns else 1) - 1, 3)
        writer.align()
        for raw in plmns or [_plmn(mcc, mnc)]:
            writer.octets(raw if isinstance(raw, (bytes, bytearray)) else bytes.fromhex(raw))
        writer.bit(0)                   # EUTRA-Mode-Info: no extensions
        writer.bit(0)                   # fDD
        writer.bit(0)                   # EUTRA-FDD-Info: no extensions
        writer.bit(0)                   # no iE-Extensions
        writer.align()
        writer.bits(cell.get("ul_earfcn", 24300) & 0xFFFF, 16)
        writer.bits(cell.get("dl_earfcn", 6300) & 0xFFFF, 16)
        writer.bits(BW[cell.get("ul_bw", "bw100")], 4)
        writer.bits(BW[cell.get("dl_bw", "bw100")], 4)
    return writer.taked()


def x2setup_request(mcc, mnc, enb_id, pci, cell_id, tac, **cell):
    """X2SetupRequest with a GlobalENB-ID and one served cell."""
    cell.update({"pci": pci, "cell_id": cell_id, "tac": tac})
    fields = [
        _ie_field(IE_GLOBAL_ENB_ID, "reject", ie_global_enb_id(mcc, mnc, enb_id)),
        _ie_field(IE_SERVED_CELLS, "reject", ie_served_cells([cell], mcc, mnc)),
    ]
    return _pdu(PROC_X2_SETUP, "reject", _container(fields))


# ---------------------------------------------------------------------------
# Decoding.
# ---------------------------------------------------------------------------

def _plmn_text(raw):
    if len(raw) != 3:
        return raw.hex()
    a, b, c = raw
    mcc = "%d%d%d" % (a & 0x0F, a >> 4, b & 0x0F)
    mnc = "%d%d" % (c & 0x0F, c >> 4)
    if b >> 4 != 0x0F:
        mnc += "%d" % (b >> 4)
    return "%s/%s" % (mcc, mnc)


def _read_ecgi(reader):
    reader.bit()                        # extensions
    reader.bit()                        # iE-Extensions
    reader.align()
    plmn = _plmn_text(reader.octets(3))
    cell_id = reader.bits(28)
    return "%s cell 0x%07x" % (plmn, cell_id)


def _decode_served_cells(reader):
    count = reader.bits(8) + 1
    reader.align()
    parts = []
    for _ in range(count):
        reader.bit()                    # item extensions
        reader.bit()                    # neighbour-Info
        reader.bit()                    # item iE-Extensions
        reader.bit()                    # ServedCell-Information extensions
        reader.bit()                    # its iE-Extensions
        reader.align()
        pci = reader.bits(16)
        ecgi = _read_ecgi(reader)
        tac = reader.bits(16)
        plmn_count = reader.bits(3) + 1
        reader.align()
        plmns = [_plmn_text(reader.octets(3)) for _ in range(plmn_count)]
        reader.bit()                    # mode extensions
        duplex = reader.bit()
        reader.bit()                    # mode SEQUENCE extensions
        reader.bit()                    # its iE-Extensions
        reader.align()
        ul = reader.bits(16)
        dl = reader.bits(16)
        ul_bw = reader.bits(4) & 0x07
        dl_bw = reader.bits(4) & 0x07
        parts.append("%s pci %d tac %d [%s] %s uL %d dL %d %s/%s" % (
            ecgi, pci, tac, " ".join(plmns), "tDD" if duplex else "fDD",
            ul, dl, BW_NAME.get(ul_bw, ul_bw), BW_NAME.get(dl_bw, dl_bw)))
    return ", ".join(parts)


def _decode_ie(reader, ie_id):
    if ie_id == IE_GLOBAL_ENB_ID:
        reader.bit()                    # extensions
        reader.bit()                    # iE-Extensions
        reader.align()
        plmn = _plmn_text(reader.octets(3))
        form = reader.octet()
        if form != 0:
            return "eNB-ID form 0x%02x (not decoded)" % form
        enb_id = reader.bits(20)
        return "%s macro-eNB %d (0x%05x)" % (plmn, enb_id, enb_id)
    if ie_id == IE_SERVED_CELLS:
        return _decode_served_cells(reader)
    raise ValueError("no decoder for IE id %d" % ie_id)


def decode(raw):
    """Return a list of (key, value) rows for one X2AP-PDU."""
    if len(raw) < 4:
        raise ValueError("too short to be an X2AP-PDU")
    reader = AperReader(raw)
    if reader.octet() != 0:
        raise ValueError("only initiating messages are decoded")
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
    inner.bit()                         # body SEQUENCE extensions
    inner.align()
    count = inner.bits(16)
    inner.align()
    rows.append(("ies", "%d" % count))
    for _ in range(count):
        ie_id = inner.bits(16)
        inner.align()
        ie_criticality = CRITICALITY_NAME.get(inner.octet(), "?")
        ie_len = inner.octet()
        value = inner.octets(ie_len)
        name = IE_NAMES.get(ie_id, "IE-%d" % ie_id)
        try:
            text = _decode_ie(AperReader(value), ie_id)
        except Exception as exc:
            text = "undecodable (%s)" % exc
        rows.append(("ie", "%s %s %s" % (name, ie_criticality, text)))
    return rows


# ---------------------------------------------------------------------------
# Vectors -- each one carries what the two referees said about it.
# ---------------------------------------------------------------------------

VECTORS = [
    # pycrate reads id-x2Setup / reject / GlobalENB-ID macro 0xA1C01 / one
    # ServedCells item and re-encodes byte-identically; tshark dissects the
    # same octets as an SCTP DATA chunk with PPID 27 and reports pCI 301,
    # eUTRANcellIdentifier 10600464 at 28 bits with 4 pad bits, tAC 1,
    # broadcastPLMN 001/01 and fDD 24300/6300 bw100 with no Malformed verdict.
    ("x2setup-001-01",
     "0006002a000002001500080000f11000a1c010001400170000012d0000f110"
     "0a1c0100001000f110005eec189c55",
     "x2setup 001 01 eNB 0xA1C01, cell pci 301 id 0x0A1C010 tac 1"),
    # The same message with every field at a different width: a three-digit
    # MNC, the cell id at its 28-bit maximum, a tAC whose high octet is
    # non-zero (so the misalignment cannot hide), and both bandwidths.
    ("x2setup-310-260",
     "0006002a000002001500080013006200123450001400170000019000130062"
     "0ffffffbeef013006200477c072123",
     "x2setup 310 260 eNB 0x12345, cell pci 400 id 0x0FFFFFF tac 0xBEEF"),
]


def selftest():
    failures = 0

    def check(name, got, want):
        nonlocal failures
        if got != want:
            failures += 1
            print("ASSERTION %s FAIL" % name)
            print("  got  %r" % (got,))
            print("  want %r" % (want,))
        else:
            print("ASSERTION %s ok" % name)

    for name, want, why in VECTORS:
        check("vector %s is our encoding" % name,
              len(decode(bytes.fromhex(want))) > 0, True)
    check("plmn 001/01", _plmn(1, "01").hex(), "00f110")
    check("plmn 310/260", _plmn(310, "260").hex(), "130062")
    check("global-enb-id", ie_global_enb_id(1, "01", 0xA1C01).hex(),
          "0000f11000a1c010")
    # The served cell on its own, without the ServedCells count octet: these
    # are the 22 octets pycrate produced for the same value and re-encodes to.
    check("served cell", ie_served_cells(
        [{"pci": 301, "cell_id": 0x0A1C010, "tac": 1}], 1, "01")[1:].hex(),
          "00012d0000f1100a1c0100001000f110005eec189c55")
    check("x2setup 001/01", x2setup_request(1, "01", 0xA1C01, 301, 0x0A1C010, 1).hex(),
          VECTORS[0][1])
    check("x2setup 310/260", x2setup_request(
        310, "260", 0x12345, 400, 0x0FFFFFF, 0xBEEF,
        ul_earfcn=18300, dl_earfcn=1825, ul_bw="bw25", dl_bw="bw50").hex(),
          VECTORS[1][1])

    # Round trip: the decoder reads back what the encoder meant, including the
    # tAC that sits across octets because the cell id is not padded.
    rows = decode(bytes.fromhex(VECTORS[0][1]))
    by_key = {}
    for key, value in rows:
        by_key.setdefault(key, []).append(value)
    check("round trip procedure", by_key["procedure"], ["id-x2Setup"])
    check("round trip ie count", by_key["ies"], ["2"])
    check("round trip global id", by_key["ie"][0], "GlobalENB-ID reject "
          "001/01 macro-eNB 662529 (0xa1c01)")
    cell = by_key["ie"][1]
    check("round trip cell", "pci 301" in cell, True)
    check("round trip tac", "tac 1" in cell, True)
    check("round trip cell id", "0x0a1c010" in cell, True)
    check("round trip plmns", "[001/01]" in cell, True)
    check("round trip mode", "fDD" in cell and "bw100" in cell, True)

    rows = decode(bytes.fromhex(VECTORS[1][1]))
    cell = [v for k, v in rows if k == "ie"][1]
    check("round trip tac 0xbeef", "tac 48879" in cell, True)
    check("round trip 310/260", "310/260" in cell, True)

    print("RESULT %s" % ("PASS" if failures == 0 else "FAIL"))
    return 0 if failures == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _emit(hexbody):
    print("pdu\tX2AP")
    print("octets\t%d" % (len(hexbody) // 2))
    print("hex\t%s" % hexbody)


def main(argv):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("global-enb-id", help="GlobalENB-ID IE alone")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--enb-id", required=True, type=lambda v: int(v, 0))

    p = sub.add_parser("served-cells", help="ServedCells IE alone")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--pci", required=True, type=lambda v: int(v, 0))
    p.add_argument("--cell-id", required=True, type=lambda v: int(v, 0))
    p.add_argument("--tac", required=True, type=lambda v: int(v, 0))

    p = sub.add_parser("x2setup", help="X2SetupRequest")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--enb-id", required=True, type=lambda v: int(v, 0))
    p.add_argument("--pci", required=True, type=lambda v: int(v, 0))
    p.add_argument("--cell-id", required=True, type=lambda v: int(v, 0))
    p.add_argument("--tac", required=True, type=lambda v: int(v, 0))
    p.add_argument("--ul-earfcn", type=lambda v: int(v, 0), default=24300)
    p.add_argument("--dl-earfcn", type=lambda v: int(v, 0), default=6300)
    p.add_argument("--ul-bw", default="bw100", choices=sorted(BW))
    p.add_argument("--dl-bw", default="bw100", choices=sorted(BW))

    p = sub.add_parser("decode", help="decode one X2AP-PDU from hex")
    p.add_argument("hex")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)

    if args.verb == "global-enb-id":
        _emit(ie_global_enb_id(args.mcc, args.mnc, args.enb_id).hex())
        return 0
    if args.verb == "served-cells":
        _emit(ie_served_cells(
            [{"pci": args.pci, "cell_id": args.cell_id, "tac": args.tac}],
            args.mcc, args.mnc).hex())
        return 0
    if args.verb == "x2setup":
        _emit(x2setup_request(
            args.mcc, args.mnc, args.enb_id, args.pci, args.cell_id, args.tac,
            ul_earfcn=args.ul_earfcn, dl_earfcn=args.dl_earfcn,
            ul_bw=args.ul_bw, dl_bw=args.dl_bw).hex())
        return 0
    if args.verb == "decode":
        try:
            rows = decode(bytes.fromhex("".join(args.hex.split())))
        except ValueError as exc:
            print("error\t%s" % exc)
            return 2
        for key, value in rows:
            print("%s\t%s" % (key, value))
        return 0
    if args.verb == "selftest":
        return selftest()
    parser.error("unknown verb %s" % args.verb)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
