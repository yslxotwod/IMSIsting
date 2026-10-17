#!/usr/bin/env python3
"""
HNBAP over APER -- TS 25.469 message bodies, encoded to real octets.

Why this exists.  `modules/37_femtocell.sh --iuh` printed a four-row table that
named HNBAP, RUA and RANAP and then stopped: there was no HNBAP body anywhere
in the tree, so the 3G half of the backhaul story was a reference and not a
capability.  This file is the HNBAP side of closing that -- the two messages a
Home NodeB sends first when it comes up and when a handset appears behind it.

Why it is not part of tools/lte_asn1.py or tools/s1ap_asn1.py.  LTE RRC is
unaligned PER, S1AP is aligned PER with its own module, and HNBAP is aligned
PER again but with a *different* set of constraints and its own IE id space.
Nothing is shared between them except the word APER.

What is verified and how.  Every vector below was produced by pycrate 0.8.1
(pycrate_asn1dir.HNBAP), an independent implementation of the same ASN.1, and
this file's encoder reproduces those octets exactly.  pycrate is not a
dependency of this tree: the oracle ran once, off-tree, and the conclusion is
recorded next to each rule.  Where the clause's table and pycrate could be read
two ways, the byte that pycrate emits decided it.

The rules this file learned the hard way, all of them measurable:

  Envelope            procedureCode two octets, criticality one, then a ONE
                      octet open-type length, then the contents.  The contents
                      begin with a preamble octet (extension bit, iE-Extensions
                      absent) before the two-octet IE count.  An HNBAP
                      ProtocolIE-Container is therefore three octets of header,
                      not two -- unlike S1AP, whose S1SetupRequest has no
                      preamble.  Getting this wrong shifts the count by one
                      octet and a decoder reads 256 IEs where there are none.
  HNB-Identity        SEQUENCE { hNB-Identity-Info, iE-Extensions OPTIONAL }.
                      Preamble octet `00`, then the OCTET STRING length as a
                      16-BIT field holding (n-1) in its upper bits, then the
                      octets.  A four-octet identity opens `00 c0`.  The
                      size constraint is extensible, so one extension bit comes
                      first, and the length is (n-1) rather than n.
  CellIdentity        BIT STRING (SIZE(28)): four octets, the 28 bits flush
                      left, so 0xA1C0100 emits `a1 c0 10 00`.
  UE-Identity         CHOICE of eight, iMSI is index 0, and the IMSI itself is
                      an OCTET STRING with SIZE(3..8).  One octet of header
                      holding (n-3) in its upper bits, then the BCD octets.  An
                      eight-octet IMSI therefore opens `0a`.
  Registration-Cause  extensible ENUMERATED: the octet is 0bEII00000, so
                      emergency-call is 0x00, normal is 0x40 and
                      ue-relocation is 0x80.  The bare index decodes as an
                      extension marker and the body loses sync one field later.

NOT ENCODED, and deliberately: HNB-Deregister, UE-Deregister, UE-Capabilities,
LAC/RAC/PLMNidentity/SAC and the location IEs.  Each needs its own rule derived
the same way; none is guessed here.  `decode` names an unknown IE by id and
length rather than inventing a meaning for it.

Second referee.  Both messages were replayed through tshark 4.2.2 as SCTP DATA
chunks with PPID 20 on port 29169 -- Wireshark's own decode table maps PPID 20
to HNBAP and 19 to RUA -- and it dissects them back to id-HNBRegister (1) with
id-HNB-Identity (3) 0xdeadbeef and id-CellIdentity (11) at "bit length 28, 4 LSB
pad bits", and to id-UERegister (3) with id-UE-Identity (5) reading the IMSI
digits and id-Registration-Cause (12).  No Malformed verdict.

Interfaces, not guesses: HNBAP runs over SCTP on the Iuh, PPID 20, port 29169.
This file builds the message and never opens an association, the same division
of labour every other codec in this tree keeps.

Usage:
    hnbap_asn1.py hnb-register --hnb-id deadbeef --cell-id 0xA1C0100
    hnbap_asn1.py ue-register --imsi 3102601234567809 [--cause normal]
    hnbap_asn1.py decode <hex>
    hnbap_asn1.py selftest

Output is KEY<TAB>value, one key per line, the contract every other tool in
tools/ keeps.
"""

import argparse
import sys

PROC_HNB_REGISTER = 1
PROC_HNB_DEREGISTER = 2
PROC_UE_REGISTER = 3
PROC_UE_DEREGISTER = 4

PROC_NAMES = {
    PROC_HNB_REGISTER: "HNBRegister",
    PROC_HNB_DEREGISTER: "HNBDeRegister",
    PROC_UE_REGISTER: "UERegister",
    PROC_UE_DEREGISTER: "UEDeRegister",
}

IE_HNB_IDENTITY = 3
IE_CELL_IDENTITY = 11
IE_UE_IDENTITY = 5
IE_REGISTRATION_CAUSE = 12

IE_NAMES = {
    IE_HNB_IDENTITY: "HNB-Identity",
    IE_CELL_IDENTITY: "CellIdentity",
    IE_UE_IDENTITY: "UE-Identity",
    IE_REGISTRATION_CAUSE: "Registration-Cause",
}

CRITICALITY = {"reject": 0x00, "ignore": 0x40, "notify": 0x80}
CRITICALITY_NAMES = {v: k for k, v in CRITICALITY.items()}

CAUSES = ["emergency-call", "normal", "ue-relocation"]

# HNBAP rides SCTP; there is no IANA PPID registration for it in the same sense
# that S1AP has 18, and this file never builds an SCTP chunk.  The port is
# Iuh's well-known one and is reported so a caller knows where it would go.
IUH_PORT = 29169


def norm_hex(text):
    """Strip 0x, separators and case from a hex string."""
    h = text.strip().replace("0x", "").replace("0X", "")
    for ch in " \t\r\n:.-":
        h = h.replace(ch, "")
    h = h.lower()
    if h and (len(h) % 2 or any(c not in "0123456789abcdef" for c in h)):
        raise ValueError("not hex: %s" % text)
    return h


def ie(ie_id, value, criticality="reject"):
    """One ProtocolIE-Field: id two octets, criticality one, open type."""
    if len(value) > 255:
        raise ValueError("IE %d value is %d octets; the open type is one octet"
                         % (ie_id, len(value)))
    return (ie_id.to_bytes(2, "big") + bytes([CRITICALITY[criticality]])
            + bytes([len(value)]) + value)


def container(ies, preamble=True):
    """The IE container: preamble octet, two-octet count, the fields."""
    head = b"\x00" if preamble else b""
    return head + len(ies).to_bytes(2, "big") + b"".join(ies)


def pdu(procedure, body, criticality="reject"):
    """The initiatingMessage envelope around a container."""
    if len(body) > 255:
        raise ValueError("body is %d octets; the open type is one octet"
                         % len(body))
    return (procedure.to_bytes(2, "big") + bytes([CRITICALITY[criticality]])
            + bytes([len(body)]) + body)


# --- the IEs this file can build -------------------------------------------

def ie_hnb_identity(info_hex):
    """
    HNB-Identity ::= SEQUENCE { hNB-Identity-Info, iE-Extensions OPTIONAL }.

    Two octets of header, not three: the 16-bit field carries the extension
    bit, the iE-Extensions bit and the OCTET STRING length as (n-1) in its
    upper bits.  A four-octet identity opens `00 c0`, which pycrate emits for
    {'hNB-Identity-Info': b'\\xde\\xad\\xbe\\xef'} and nothing else.
    """
    data = bytes.fromhex(norm_hex(info_hex))
    if not 1 <= len(data) <= 64:
        raise ValueError("an HNB identity is 1..64 octets, got %d" % len(data))
    length = (len(data) - 1) << 6
    return length.to_bytes(2, "big") + data


def ie_cell_identity(cell_id):
    """
    CellIdentity ::= BIT STRING (SIZE(28)) -- four octets, flush left.

    0xA1C0100 is the value pycrate writes for the reference vector and the one
    tshark reads back as `a1 c0 10 00`.
    """
    v = cell_id & 0x0FFFFFFF
    return (v << 4).to_bytes(4, "big")


def ie_ue_identity(imsi_hex):
    """
    UE-Identity ::= CHOICE { iMSI OCTET STRING (SIZE(3..8)), ... }.

    iMSI is index 0 of eight alternatives, so the leading bits are zero, and
    the one octet of header left over holds (n-3) in its upper bits: a
    three-octet IMSI opens `00`, an eight-octet IMSI opens `0a`.
    """
    data = bytes.fromhex(norm_hex(imsi_hex))
    if not 3 <= len(data) <= 8:
        raise ValueError("an IMSI is 3..8 octets, got %d" % len(data))
    return bytes([(len(data) - 3) << 1]) + data


def ie_registration_cause(cause):
    """Registration-Cause ::= ENUMERATED { emergency-call, normal,
    ue-relocation, ... } -- extensible, so the octet is 0bEII00000."""
    if cause not in CAUSES:
        raise ValueError("cause must be one of %s" % ", ".join(CAUSES))
    return bytes([CAUSES.index(cause) << 6])


# --- the two messages -------------------------------------------------------

def hnb_register(hnb_id_hex, cell_id, criticality="reject"):
    ies = [ie(IE_HNB_IDENTITY, ie_hnb_identity(hnb_id_hex), criticality),
           ie(IE_CELL_IDENTITY, ie_cell_identity(cell_id), criticality)]
    return pdu(PROC_HNB_REGISTER, container(ies), criticality)


def ue_register(imsi_hex, cause="normal", criticality="reject"):
    ies = [ie(IE_UE_IDENTITY, ie_ue_identity(imsi_hex), criticality),
           ie(IE_REGISTRATION_CAUSE, ie_registration_cause(cause), criticality)]
    return pdu(PROC_UE_REGISTER, container(ies), criticality)


# --- reading one back -------------------------------------------------------

def decode(hex_text):
    """
    Read an HNBAP initiatingMessage back into KEY<TAB>value rows.

    Deliberately strict: an unknown IE is printed with its id and length rather
    than a name invented for it, and a length that overruns the buffer is an
    error instead of a silent truncation.
    """
    data = bytes.fromhex(norm_hex(hex_text))
    if len(data) < 4:
        raise ValueError("too short to be an HNBAP PDU: %d octets" % len(data))
    proc = int.from_bytes(data[0:2], "big")
    crit = CRITICALITY_NAMES.get(data[2], "0x%02x" % data[2])
    blen = data[3]
    body = data[4:4 + blen]
    if len(body) < blen:
        raise ValueError("open type says %d octets, only %d present"
                         % (blen, len(body)))
    if not body:
        raise ValueError("empty container")
    if body[0] not in (0x00, 0x40, 0x80):
        # The preamble octet carries the extension bit and iE-Extensions; for
        # every message this file builds it is 0x00.
        raise ValueError("unexpected container preamble 0x%02x" % body[0])
    if len(body) < 3:
        raise ValueError("container is %d octets; needs three of header"
                         % len(body))
    count = int.from_bytes(body[1:3], "big")
    rows = [("message", "initiatingMessage"),
            ("procedure", PROC_NAMES.get(proc, "id-%d" % proc)),
            ("procedure_code", str(proc)),
            ("criticality", crit),
            ("open_type_octets", str(blen)),
            ("ies", str(count))]

    off = 3
    for index in range(count):
        if off + 4 > len(body):
            raise ValueError("IE %d starts past the end of the container" % index)
        ie_id = int.from_bytes(body[off:off + 2], "big")
        ie_crit = CRITICALITY_NAMES.get(body[off + 2], "0x%02x" % body[off + 2])
        ie_len = body[off + 3]
        value = body[off + 4:off + 4 + ie_len]
        if len(value) != ie_len:
            raise ValueError("IE %d says %d octets, only %d present"
                             % (ie_id, ie_len, len(value)))
        off += 4 + ie_len
        name = IE_NAMES.get(ie_id, "id-%d" % ie_id)
        rows.append(("ie", "%s %s %s" % (name, ie_crit, value.hex())))
        if ie_id == IE_HNB_IDENTITY and len(value) >= 3:
            length = (int.from_bytes(value[1:3], "big") >> 6) + 1
            rows.append(("hnb_identity", value[2:2 + length].hex()))
        elif ie_id == IE_CELL_IDENTITY and len(value) == 4:
            rows.append(("cell_identity",
                         "%08x" % (int.from_bytes(value, "big") >> 4)))
        elif ie_id == IE_UE_IDENTITY and len(value) >= 1:
            length = (value[0] >> 1) + 3
            rows.append(("imsi", value[1:1 + length].hex()))
        elif ie_id == IE_REGISTRATION_CAUSE and len(value) == 1:
            idx = value[0] >> 6
            rows.append(("registration_cause",
                         CAUSES[idx] if idx < len(CAUSES) else str(idx)))
    if off != len(body):
        raise ValueError("%d octets left over after %d IEs"
                         % (len(body) - off, count))
    return rows


# --- vectors, and the selftest that holds this file to them -----------------

# pycrate 0.8.1, off-tree, one run each.  The comment says what the oracle was
# asked for, so a later reader can re-run the check without guessing.
VECTORS = [
    # HNBRegisterRequest with HNB-Identity 'deadbeef' and CellIdentity 0xA1C0100
    ("hnb-register", "000100150000020003000600c0deadbeef000b0004a1c01000",
     {"hnb_id": "deadbeef", "cell_id": "0a1c0100"}),
    # UERegisterRequest with iMSI 3102601234567809 and cause normal
    ("ue-register", "00030015000002000500090a3102601234567809000c000140",
     {"imsi": "3102601234567809", "cause": "normal"}),
]


def selftest():
    checks = []
    failed = 0

    def chk(label, got, want):
        nonlocal failed
        ok = got == want
        if not ok:
            failed += 1
            print("FAIL\t%s\tgot %r want %r" % (label, got, want))
        checks.append(label)

    # 1. the two full messages reproduce the oracle octet for octet
    hnb = hnb_register("deadbeef", 0x0A1C0100).hex()
    chk("hnb-register", hnb, VECTORS[0][1])
    ue = ue_register("3102601234567809", "normal").hex()
    chk("ue-register", ue, VECTORS[1][1])

    # 2. lengths and ports a caller needs
    chk("hnb-octets", str(len(hnb) // 2), "25")
    chk("ue-octets", str(len(ue) // 2), "25")
    chk("iuh-port", str(IUH_PORT), "29169")

    # 3. the single-IE vectors that pinned the field rules
    chk("hnb-identity-1", ie_hnb_identity("00").hex(), "000000")
    chk("hnb-identity-2", ie_hnb_identity("0001").hex(), "00400001")
    chk("hnb-identity-4", ie_hnb_identity("00010203").hex(), "00c000010203")
    chk("hnb-identity-8", ie_hnb_identity("0001020304050607").hex(),
        "01c00001020304050607")
    chk("cell-identity", ie_cell_identity(0x0A1C0100).hex(), "a1c01000")
    chk("cell-identity-1", ie_cell_identity(0x1).hex(), "00000010")
    chk("ue-identity-3", ie_ue_identity("000102").hex(), "00000102")
    chk("ue-identity-4", ie_ue_identity("00010203").hex(), "0200010203")
    chk("ue-identity-8", ie_ue_identity("0001020304050607").hex(),
        "0a0001020304050607")
    chk("cause-emergency", ie_registration_cause("emergency-call").hex(), "00")
    chk("cause-normal", ie_registration_cause("normal").hex(), "40")
    chk("cause-relocation", ie_registration_cause("ue-relocation").hex(), "80")

    # 4. an empty container is three octets of header, not two -- the rule that
    #    separates HNBAP from S1AP and the one a decoder gets wrong silently
    chk("container-empty", container([]).hex(), "000000")
    chk("pdu-empty", pdu(PROC_HNB_REGISTER, container([])).hex(),
        "00010003000000")

    # 5. the decoder reads back what the encoder wrote
    rows = dict(decode(hnb))
    chk("decode-procedure", rows["procedure"], "HNBRegister")
    chk("decode-ies", rows["ies"], "2")
    chk("decode-hnb-id", rows["hnb_identity"], "deadbeef")
    chk("decode-cell", rows["cell_identity"], "0a1c0100")
    rows = dict(decode(ue))
    chk("decode-ue-procedure", rows["procedure"], "UERegister")
    chk("decode-imsi", rows["imsi"], "3102601234567809")
    chk("decode-cause", rows["registration_cause"], "normal")

    # 6. refusals are refusals, not plausible output
    try:
        ie_ue_identity("0001")
        chk("ue-identity-too-short", "accepted", "refused")
    except ValueError:
        chk("ue-identity-too-short", "refused", "refused")
    try:
        ie_ue_identity("00" * 9)
        chk("ue-identity-too-long", "accepted", "refused")
    except ValueError:
        chk("ue-identity-too-long", "refused", "refused")
    try:
        ie_registration_cause("urgent")
        chk("cause-unknown", "accepted", "refused")
    except ValueError:
        chk("cause-unknown", "refused", "refused")
    try:
        decode("0011")
        chk("decode-short", "accepted", "refused")
    except ValueError:
        chk("decode-short", "refused", "refused")
    # a count that overruns the container must not read past it
    try:
        decode("000100050000090003")  # one IE claimed given three octets
        chk("decode-overrun", "accepted", "refused")
    except ValueError:
        chk("decode-overrun", "refused", "refused")

    print("ASSERTIONS\t%d" % len(checks))
    print("RESULT\t%s" % ("PASS" if failed == 0 else "FAIL"))
    return 1 if failed else 0


def main(argv):
    p = argparse.ArgumentParser(prog="hnbap_asn1.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("hnb-register", help="HNBRegisterRequest")
    a.add_argument("--hnb-id", required=True,
                   help="HNB-Identity-Info, 1..64 octets as hex")
    a.add_argument("--cell-id", required=True, type=lambda v: int(v, 0),
                   help="CellIdentity, 28 bits")
    a.add_argument("--criticality", default="reject", choices=sorted(CRITICALITY))

    b = sub.add_parser("ue-register", help="UERegisterRequest")
    b.add_argument("--imsi", required=True, help="IMSI BCD, 3..8 octets as hex")
    b.add_argument("--cause", default="normal", choices=CAUSES)
    b.add_argument("--criticality", default="reject", choices=sorted(CRITICALITY))

    c = sub.add_parser("decode", help="read an HNBAP PDU back")
    c.add_argument("hex")

    sub.add_parser("selftest")

    args = p.parse_args(argv)

    if args.cmd == "selftest":
        return selftest()

    try:
        if args.cmd == "hnb-register":
            body = hnb_register(args.hnb_id, args.cell_id, args.criticality)
            print("message\t%s" % PROC_NAMES[PROC_HNB_REGISTER])
            print("hnbap_hex\t%s" % body.hex())
            print("hnbap_octets\t%d" % len(body))
            print("hnb_identity\t%s" % norm_hex(args.hnb_id))
            print("cell_identity\t%08x" % (args.cell_id & 0x0FFFFFFF))
            print("transport\tSCTP")
            print("iuh_port\t%d" % IUH_PORT)
            print("status\tbuilt")
            print("next\tbind an SCTP association to a test HNB-GW; this "
                  "file builds the message and opens nothing")
            return 0
        if args.cmd == "ue-register":
            body = ue_register(args.imsi, args.cause, args.criticality)
            print("message\t%s" % PROC_NAMES[PROC_UE_REGISTER])
            print("hnbap_hex\t%s" % body.hex())
            print("hnbap_octets\t%d" % len(body))
            print("imsi\t%s" % norm_hex(args.imsi))
            print("registration_cause\t%s" % args.cause)
            print("transport\tSCTP")
            print("iuh_port\t%d" % IUH_PORT)
            print("status\tbuilt")
            print("next\tbind an SCTP association to a test HNB-GW; this "
                  "file builds the message and opens nothing")
            return 0
        for key, value in decode(args.hex):
            print("%s\t%s" % (key, value))
        return 0
    except ValueError as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
