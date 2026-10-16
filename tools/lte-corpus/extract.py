#!/usr/bin/env python3
"""Extract LTE RRC PDUs from the two capture formats used by tools/lte-corpus/.

Both formats are pcap files whose payload is a real over-the-air RRC PDU
retrieved from a phone/sniffer -- no ASN.1 encoder is involved anywhere.

  qcsuper <pcap>   raw-IPv4 pcap (link type 228) wrapping GSMTAP/UDP port 4729
                   (QCSuper re-encapsulates the phone's Qualcomm diag log);
                   GSMTAP type 13 = GSMTAP_TYPE_LTE_RRC, and the sub-type byte
                   at offset 12 selects the logical channel:
                     5 = GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message  (SIB1, SI)
                     6 = GSMTAP_LTE_RRC_SUB_PCCH_Message         (paging)
                   (values from Wireshark epan/dissectors/packet-gsmtap.c).
                   The GSMTAP header length is byte 1 counted in 32-bit words,
                   so the payload starts at gsmtap + (byte1 << 2).

  srsran <pcap>    link type 147 (DLT_USER0) holding the srsRAN
                   "mac-lte-framed" context that Wireshark's packet-mac-lte.c
                   dissector expects. Layout (srsRAN
                   lib/src/common/pcap.c LTE_PCAP_PACK_MAC_CONTEXT_TO_BUFFER):
                     byte0 radioType, byte1 direction, byte2 rntiType
                     then tag/value pairs:
                       0x02 RNTI(2)  0x03 UEID(2)  0x04 SFN<<4|subframe(2)
                       0x07 CRC status(1)  0x0a carrier(1)  0x0f NB mode(1)
                       0x01 PAYLOAD -- the rest of the packet, no length byte.

Usage:  python3 tools/lte-corpus/extract.py {qcsuper|srsran} <pcap> [--distinct]

Exit:   0 extracted, 2 the file is not in the expected format.
"""

import binascii
import json
import struct
import sys

MAC_LTE_PAYLOAD_TAG = 0x01
MAC_LTE_RNTI_TAG = 0x02
MAC_LTE_UEID_TAG = 0x03
MAC_LTE_FRAME_SUBFRAME_TAG = 0x04
MAC_LTE_CRC_STATUS_TAG = 0x07
MAC_LTE_CARRIER_ID_TAG = 0x0A
MAC_LTE_NB_MODE_TAG = 0x0F
MAC_LTE_CE_MODE_TAG = 0x0E
MAC_LTE_SI_RNTI = 0xFFFF

GSMTAP_TYPE_LTE_RRC = 13
GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH = 5
GSMTAP_LTE_RRC_SUB_PCCH = 6

LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_USER0 = 147


class FormatError(SystemExit):
    def __init__(self, msg):
        SystemExit.__init__(self, "extract.py: %s" % msg)


def read_pcap(path):
    """Yield (frame_number, link_type, packet_bytes) for every record."""
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise FormatError("%s: not a classic pcap file (magic %r); pcapng is "
                          "not supported" % (path, magic))
    link_type = struct.unpack_from(endian + "I", data, 20)[0]
    off = 24
    n = 0
    while off + 16 <= len(data):
        _ts, _tus, caplen, _origlen = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        n += 1
        yield n, link_type, data[off:off + caplen]
        off += caplen


def qcsuper_frames(path):
    """GSMTAP-encapsulated LTE RRC PDUs from a QCSuper-style pcap."""
    out = []
    for n, link_type, pkt in read_pcap(path):
        if link_type not in (LINKTYPE_RAW, LINKTYPE_IPV4):
            raise FormatError("%s: frame %d has link type %d, expected raw IPv4 "
                              "(101 or 228)" % (path, n, link_type))
        if len(pkt) < 20 + 8:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if pkt[9] != 17:                      # UDP
            continue
        sport, dport, ulen = struct.unpack_from(">HHH", pkt, ihl)
        if dport != 4729 and sport != 4729:   # GSMTAP
            continue
        g = ihl + 8
        if len(pkt) < g + 16:
            continue
        gtype = pkt[g + 2]
        if gtype != GSMTAP_TYPE_LTE_RRC:
            continue
        hlen = pkt[g + 1] << 2                # header length is in 32-bit words
        if hlen < 16 or len(pkt) < g + hlen:
            raise FormatError("%s: frame %d declares a %d-byte GSMTAP header"
                              % (path, n, hlen))
        payload = pkt[g + hlen:ihl + ulen]
        if not payload:
            continue
        out.append({
            "frame": n,
            "gsmtap_type": gtype,
            "gsmtap_sub_type": pkt[g + 12],
            "channel": {GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH: "BCCH-DL-SCH",
                        GSMTAP_LTE_RRC_SUB_PCCH: "PCCH"}.get(pkt[g + 12],
                                                             "sub_type_%d" % pkt[g + 12]),
            "pdu": binascii.hexlify(payload).decode(),
        })
    return out


def srsran_frames(path):
    """MAC PDUs from an srsRAN 'mac-lte-framed' pcap (DLT_USER0)."""
    tag_len = {
        MAC_LTE_RNTI_TAG: 2,
        MAC_LTE_UEID_TAG: 2,
        MAC_LTE_FRAME_SUBFRAME_TAG: 2,
        MAC_LTE_CRC_STATUS_TAG: 1,
        MAC_LTE_CARRIER_ID_TAG: 1,
        MAC_LTE_NB_MODE_TAG: 1,
        MAC_LTE_CE_MODE_TAG: 1,
    }
    out = []
    for n, link_type, pkt in read_pcap(path):
        if link_type != LINKTYPE_USER0:
            raise FormatError("%s: frame %d has link type %d, expected 147 "
                              "(DLT_USER0)" % (path, n, link_type))
        if len(pkt) < 4:
            continue
        radio, direction, rnti_type = pkt[0], pkt[1], pkt[2]
        i = 3
        tags = {}
        while i < len(pkt):
            tag = pkt[i]
            if tag == MAC_LTE_PAYLOAD_TAG:
                i += 1
                break
            if tag not in tag_len:
                raise FormatError("%s: frame %d has unknown MAC context tag 0x%02x"
                                  % (path, n, tag))
            ln = tag_len[tag]
            tags[tag] = pkt[i + 1:i + 1 + ln]
            i += 1 + ln
        payload = pkt[i:]
        if not payload:
            continue
        rnti = int.from_bytes(tags.get(MAC_LTE_RNTI_TAG, b"\0\0"), "big")
        sfn_sf = int.from_bytes(tags.get(MAC_LTE_FRAME_SUBFRAME_TAG, b"\0\0"), "big")
        out.append({
            "frame": n,
            "radio": radio,
            "direction": direction,
            "rnti_type": rnti_type,
            "rnti": rnti,
            "sfn": sfn_sf >> 4,
            "subframe": sfn_sf & 0xF,
            "crc_ok": tags.get(MAC_LTE_CRC_STATUS_TAG, b"").hex(),
            "channel": "SI-RNTI" if rnti == MAC_LTE_SI_RNTI else "rnti_0x%04x" % rnti,
            "pdu": binascii.hexlify(payload).decode(),
        })
    return out


EXTRACTORS = {"qcsuper": qcsuper_frames, "srsran": srsran_frames}


def main(argv):
    if len(argv) < 3 or argv[1] not in EXTRACTORS:
        sys.stderr.write(__doc__)
        return 2
    which, path = argv[1], argv[2]
    frames = EXTRACTORS[which](path)
    if "--distinct" in argv[3:]:
        seen = {}
        for fr in frames:
            seen.setdefault(fr["pdu"], fr)
        frames = list(seen.values())
    print(json.dumps(frames, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
