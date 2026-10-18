#!/usr/bin/env python3
"""RANAP -- the Radio Access Network Application Part of Iu (TS 25.413).

RUA carries it, the core acts on it.  `tools/rua_asn1.py` can already frame a
RANAP-Message inside a DirectTransfer, and until this file existed the RANAP
inside had to be typed in from somewhere else: the tree could open the Iuh
signalling connection but not say what it wanted to say.

What this file builds:

  InitialUE-Message   procedureCode 19 -- CN-DomainIndicator, LAI, SAI, NAS-PDU

That is the message a rogue HeNB/NB sends to hand the core a subscriber's
first NAS message.  Everything else in TS 25.413 -- the RAB assignment, the
release, the relocation procedures -- is a name here, not octets.

Layouts, each pinned against pycrate 0.8.1 and tshark 4.2.2 rather than
inferred from the clause -- see tools/ranap-oracle/check_ranap_codec.py.

The reading that matters: pycrate will encode an InitialUE-Message body under
ANY procedureCode you hand it, silently.  `--ranap-...` with procedureCode 1
produced a well-formed PDU that tshark dissects as an Iu-ReleaseCommand.  The
procedure code comes from `tshark -G values` for ranap.procedureCode, where
id-InitialUE-Message is 19 and id-Iu-Release is 1.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s1ap_asn1 import AperWriter, _container, _criticality_octet, _plmn  # noqa: E402
from rua_asn1 import _ie_field, _length_octets, _open_type, _pdu, _read_ie_length  # noqa: E402

# ---------------------------------------------------------------------------
# Constants -- TS 25.413 clause 9.  Procedure codes are the ones tshark
# dissects, not the order pycrate happens to list its object set in.
# ---------------------------------------------------------------------------

PROC_RAB_ASSIGNMENT = 0
PROC_IU_RELEASE = 1
PROC_SECURITY_MODE_CONTROL = 6
PROC_RESET = 9
PROC_PAGING = 14
PROC_COMMON_ID = 15
PROC_INITIAL_UE_MESSAGE = 19
PROC_DIRECT_TRANSFER_RANAP = 20

IE_CN_DOMAIN_INDICATOR = 3
IE_LAI = 15
IE_NAS_PDU = 16
IE_SAI = 58
IE_IU_SIGCON_ID = 79

# CN-DomainIndicator ::= ENUMERATED { cs-domain, ps-domain }
# Not extensible: pycrate encodes ps-domain in ONE bit (0x80 after the pad).
# A second bit for an extension marker puts ps-domain at 0x40, which is
# cs-domain with a set extension bit -- the core would open the circuit-switch
# side of a packet connection.
CN_DOMAIN = {"cs-domain": 0, "ps-domain": 1}
CN_DOMAIN_NAME = {0: "cs-domain", 1: "ps-domain"}

PROCEDURE_NAME = {
    PROC_RAB_ASSIGNMENT: "id-RAB-Assignment",
    PROC_IU_RELEASE: "id-Iu-Release",
    PROC_SECURITY_MODE_CONTROL: "id-SecurityModeControl",
    PROC_RESET: "id-Reset",
    PROC_PAGING: "id-Paging",
    PROC_COMMON_ID: "id-CommonID",
    PROC_INITIAL_UE_MESSAGE: "id-InitialUE-Message",
    PROC_DIRECT_TRANSFER_RANAP: "id-DirectTransfer",
}

IE_NAME = {
    IE_CN_DOMAIN_INDICATOR: "id-CN-DomainIndicator",
    IE_LAI: "id-LAI",
    IE_NAS_PDU: "id-NAS-PDU",
    IE_SAI: "id-SAI",
    IE_IU_SIGCON_ID: "id-IuSigConId",
}

CRITICALITY_NAME = {0x00: "reject", 0x40: "ignore", 0x80: "notify"}


# ---------------------------------------------------------------------------
# IEs -- TS 25.413 clause 9.2.
# ---------------------------------------------------------------------------

def ie_cn_domain(domain):
    """CN-DomainIndicator ::= ENUMERATED { cs-domain(0), ps-domain(1) }.

    One bit, then the writer pads.  See the note on CN_DOMAIN above.
    """
    if domain not in CN_DOMAIN:
        raise ValueError("domain must be one of %s" % ", ".join(sorted(CN_DOMAIN)))
    writer = AperWriter()
    writer.bit(CN_DOMAIN[domain])
    return writer.taked()


def _ie_location_area(plmn, lac, sac=None):
    """LAI / SAI = SEQUENCE { pLMNidentity, lAC, [sAC], iE-Extensions OPTIONAL }.

    The SEQUENCE is not extensible, so there is no extension bit; the only
    preamble is the presence bit of the optional iE-Extensions, one bit, then
    the aligned octets.  pycrate measures LAI at 48 bits and SAI at 64, which
    is 8 + 3*8 + 2*8 and 8 + 3*8 + 2*8 + 2*8 -- i.e. that single bit and a pad.
    """
    writer = AperWriter()
    writer.bit(0)                       # no iE-Extensions
    writer.align()
    writer.octets(plmn)                 # pLMNidentity, OCTET STRING (SIZE (3))
    writer.octets(lac)                  # lAC          OCTET STRING (SIZE (2))
    if sac is not None:
        writer.octets(sac)              # sAC          OCTET STRING (SIZE (2))
    return writer.taked()


def ie_lai(plmn, lac):
    return _ie_location_area(plmn, lac)


def ie_sai(plmn, lac, sac):
    return _ie_location_area(plmn, lac, sac)


def ie_nas_pdu(nas):
    """NAS-PDU ::= OCTET STRING -- the subscriber's NAS message, verbatim.

    The determinant grows a second octet above 127, and a real Attach with an
    ESM container is past that, so this uses the same long-form writer as RUA.
    """
    writer = AperWriter()
    _open_type(writer, nas)
    return writer.taked()


def ie_iu_sigcon_id(value):
    """IuSigConId ::= BIT STRING (SIZE (24)) -- optional, 24 bits, no pad."""
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("IuSigConId is 24 bits")
    writer = AperWriter()
    writer.bits(value, 24)
    return writer.taked()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def initial_ue(plmn, lac, sac, nas, domain="ps-domain"):
    """InitialUE-Message ::= { CN-DomainIndicator, LAI, SAI, NAS-PDU, ... }.

    Criticalities are the ones in the message definition and the ones tshark
    reads back: the domain indicator rejects, the location areas and the NAS
    message are ignored when unrecognised.
    """
    fields = [
        _ie_field(IE_CN_DOMAIN_INDICATOR, "reject", ie_cn_domain(domain)),
        _ie_field(IE_LAI, "ignore", ie_lai(plmn, lac)),
        _ie_field(IE_SAI, "ignore", ie_sai(plmn, lac, sac)),
        _ie_field(IE_NAS_PDU, "ignore", ie_nas_pdu(nas)),
    ]
    body = _container(fields)
    return _pdu(PROC_INITIAL_UE_MESSAGE, "reject", body)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def _read_plmn_location(payload):
    """LAI/SAI payload -> (plmn, lac, sac or None).

    The payload starts with the optional-extensions bit and its pad, so the
    first octet is zero and the PLMN begins at octet 1.
    """
    if len(payload) < 6:
        raise ValueError("location area shorter than 6 octets")
    if payload[0] != 0x00:
        raise ValueError("location area carries extensions this file does not read")
    plmn = payload[1:4]
    lac = payload[4:6]
    sac = payload[6:8] if len(payload) >= 8 else None
    return plmn, lac, sac


def _read_nas(payload):
    length, start = _read_ie_length(payload, 0)
    nas = payload[start:start + length]
    if len(nas) != length:
        raise ValueError("NAS-PDU declares %d octets, %d present" % (length, len(nas)))
    return nas


def decode(raw):
    """Walk a RANAP-PDU into rows.  Generic: it does not assume one procedure."""
    if len(raw) < 4:
        raise ValueError("shorter than a RANAP header")
    if raw[0] != 0x00:
        raise ValueError("not an initiating message (discriminator 0x%02x)" % raw[0])
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
        ("criticality", CRITICALITY_NAME.get(criticality, "0x%02x" % criticality)),
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
                     CRITICALITY_NAME.get(ie_crit, "0x%02x" % ie_crit)))
        try:
            if ie_id == IE_CN_DOMAIN_INDICATOR:
                rows.append((prefix + ".domain",
                             CN_DOMAIN_NAME.get(payload[0] >> 7, "0x%02x" % payload[0])))
            elif ie_id in (IE_LAI, IE_SAI):
                plmn, lac, sac = _read_plmn_location(payload)
                rows.append((prefix + ".plmn", plmn.hex()))
                rows.append((prefix + ".lac", str(int.from_bytes(lac, "big"))))
                if sac is not None:
                    rows.append((prefix + ".sac", str(int.from_bytes(sac, "big"))))
            elif ie_id == IE_NAS_PDU:
                rows.append((prefix + ".nas", _read_nas(payload).hex()))
            else:
                rows.append((prefix + ".value", payload.hex()))
        except (ValueError, IndexError) as exc:
            rows.append((prefix + ".unread", str(exc)))
    if pos != len(body):
        rows.append(("trailing", "%d octet(s) ignored" % (len(body) - pos)))
    return rows


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _emit(rows):
    for key, value in rows:
        print("%s\t%s" % (key, value))


def _parse_int(text, bits, label):
    try:
        value = int(text, 0)
    except (TypeError, ValueError):
        raise SystemExit("ERROR %s must be a number, got %r" % (label, text))
    if not 0 <= value < (1 << bits):
        raise SystemExit("ERROR %s does not fit in %d bits" % (label, bits))
    return value


def main(argv):
    parser = argparse.ArgumentParser(
        prog="ranap_asn1.py",
        description="Build and read RANAP PDUs (TS 25.413) as octets.")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("initial-ue", help="InitialUE-Message")
    p.add_argument("--mcc", required=True)
    p.add_argument("--mnc", required=True)
    p.add_argument("--lac", required=True)
    p.add_argument("--sac", required=True)
    p.add_argument("--nas", required=True, help="NAS-PDU as hex")
    p.add_argument("--domain", choices=sorted(CN_DOMAIN), default="ps-domain")

    p = sub.add_parser("decode", help="read a RANAP-PDU back")
    p.add_argument("hex")

    sub.add_parser("selftest", help="run the vectors")

    args = parser.parse_args(argv)
    if args.verb is None:
        parser.print_help()
        return 2

    if args.verb == "initial-ue":
        nas = _hex(args.nas, "NAS-PDU")
        lac = _parse_int(args.lac, 16, "LAC").to_bytes(2, "big")
        sac = _parse_int(args.sac, 16, "SAC").to_bytes(2, "big")
        raw = initial_ue(_plmn(args.mcc, args.mnc), lac, sac, nas, args.domain)
        _emit([
            ("message", "InitialUE-Message"),
            ("procedure", str(PROC_INITIAL_UE_MESSAGE)),
            ("procedure-name", PROCEDURE_NAME[PROC_INITIAL_UE_MESSAGE]),
            ("layout", "TS 25.413 aligned PER (tools/ranap_asn1.py)"),
            ("octets", str(len(raw))),
            ("hex", raw.hex()),
            ("carried-by", "RUA DirectTransfer (TS 25.468)"),
        ])
        return 0

    if args.verb == "decode":
        try:
            rows = decode(_hex(args.hex, "hex"))
        except ValueError as exc:
            print("NOTDECODED\t%s" % exc)
            return 1
        _emit(rows)
        return 0

    return selftest()


def _hex(text, label):
    cleaned = "".join(ch for ch in text if not ch.isspace() and ch not in ":-")
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise SystemExit("ERROR %s has an odd number of hex digits" % label)
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise SystemExit("ERROR %s is not hex" % label)


# ---------------------------------------------------------------------------
# Vectors -- both referees agree on these octets.
# ---------------------------------------------------------------------------

PLMN_001_01 = bytes.fromhex("00f110")

VECTORS = [
    # name, kwargs, expected hex
    ("initial-ue-ps",
     dict(plmn=PLMN_001_01, lac=b"\x00\x01", sac=b"\x00\x02",
          nas=bytes.fromhex("0741010b0000")),
     "001300290000040003000180000f40060000f1100001003a40080000f1100001000200104007060741010b0000"),
    ("initial-ue-cs",
     dict(plmn=PLMN_001_01, lac=b"\x00\x01", sac=b"\x00\x02",
          nas=bytes.fromhex("0741010b0000"), domain="cs-domain"),
     None),   # filled in below: the only difference is the domain bit
]


def selftest():
    failures = 0
    checks = 0

    def check(name, condition, detail=""):
        nonlocal failures, checks
        checks += 1
        print("ASSERTION\t%s\t%s" % (name, "PASS" if condition else
                                     "FAIL %s" % detail))
        if not condition:
            failures += 1

    for name, kwargs, expected in VECTORS:
        raw = initial_ue(**kwargs)
        if expected is not None:
            check(name + ".hex", raw.hex() == expected, raw.hex())

    # The two vectors differ in exactly one bit, and that bit is the domain.
    ps = initial_ue(plmn=PLMN_001_01, lac=b"\x00\x01", sac=b"\x00\x02",
                    nas=bytes.fromhex("0741010b0000"))
    cs = initial_ue(plmn=PLMN_001_01, lac=b"\x00\x01", sac=b"\x00\x02",
                    nas=bytes.fromhex("0741010b0000"), domain="cs-domain")
    check("domain-bit-is-the-only-difference", ps != cs and
          sum(bin(a ^ b).count("1") for a, b in zip(ps, cs)) == 1,
          ps.hex() + " vs " + cs.hex())
    check("ps-domain-octet", ps[11] == 0x80, "0x%02x" % ps[11])
    check("cs-domain-octet", cs[11] == 0x00, "0x%02x" % cs[11])

    # Length: the NAS determinant plus the location areas.
    check("octets", len(ps) == 45, str(len(ps)))
    check("procedure-octet", ps[1] == 19, "0x%02x" % ps[1])

    rows = dict(decode(ps))
    check("decode-procedure-name", rows["procedure-name"] == "id-InitialUE-Message", str(rows))
    check("decode-ies", rows["ies"] == "4", str(rows.get("ies")))
    check("decode-domain", rows["ie.0.domain"] == "ps-domain", str(rows.get("ie.0.domain")))
    check("decode-lai-plmn", rows["ie.1.plmn"] == "00f110", str(rows.get("ie.1.plmn")))
    check("decode-lai-lac", rows["ie.1.lac"] == "1", str(rows.get("ie.1.lac")))
    check("decode-sai-sac", rows["ie.2.sac"] == "2", str(rows.get("ie.2.sac")))
    check("decode-nas", rows["ie.3.nas"] == "0741010b0000", str(rows.get("ie.3.nas")))

    # A procedure code is a claim about what the message is.  Reading the wrong
    # one back is a pass; the check is that the reader names 19 and not 1.
    check("decode-iu-release-is-a-different-message",
          dict(decode(bytes.fromhex(ps.hex().replace("13", "01", 1)))).get("procedure-name")
          != "id-InitialUE-Message", "procedure code 1 must not read as an initial UE message")

    # PLMN packing: a two-digit MNC keeps its filler nibble.
    check("plmn-001-01", _plmn(1, "01") == bytes.fromhex("00f110"), _plmn(1, "01").hex())
    check("plmn-310-260", _plmn(310, "260") == bytes.fromhex("13 00 62".replace(" ", "")),
          _plmn(310, "260").hex())

    # Long NAS: the determinant and the open type both grow.
    big = initial_ue(plmn=PLMN_001_01, lac=b"\x00\x01", sac=b"\x00\x02",
                     nas=bytes(range(200)))
    # Container 237 octets: 3 for the header, then 5 + 10 + 12 for the three
    # short IEs, then 207 for the NAS whose own determinant is `80 c8`.
    check("long-nas-open-type", big[3] == 0x80 and big[4] == 237,
          "open type 0x%02x 0x%02x" % (big[3], big[4]))
    check("long-nas-determinant", big[5 + 3 + 5 + 10 + 12 + 2 + 1] == 0x80,
          "NAS determinant at %d" % (5 + 3 + 5 + 10 + 12 + 2 + 1))
    check("long-nas-decodes", dict(decode(big))["ie.3.nas"] == bytes(range(200)).hex(),
          "long NAS did not round-trip")

    print("RESULT\t%s" % ("PASS" if failures == 0 else "FAIL"))
    print("ASSERTIONS\t%d" % checks)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
