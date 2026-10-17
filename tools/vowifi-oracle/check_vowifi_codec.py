#!/usr/bin/env python3
"""Differential check of the IKEv2 / EAP-AKA codec in modules/36_vowifi.sh.

The statement of the clauses, written out here as code:

* RFC 7296 3.1 -- the IKEv2 header: initiator SPI (8), responder SPI (8), next
  payload (1), version (1, major 2 minor 0), exchange type (1), flags (1) with
  only I (0x08), V (0x10) and R (0x20) defined, message ID (4), length (4)
  counted from the start of the header, 28 octets in all.
* RFC 7296 3.2 -- payload types: 33 SA, 34 KE, 35 IDi, 36 IDr, 37 CERT, 38
  CERTREQ, 39 AUTH, 40 Nonce (Ni and Nr are the same type), 41 N, 42 D, 43 V,
  44 TSi, 45 TSr, 46 SK, 47 CP, 48 EAP, and the payload header of next(1),
  flags(1) whose high bit is the critical bit, length(2) counted from that
  header.
* RFC 7296 3.3.1/3.3.2 -- an SA payload is a list of proposals and a proposal
  a list of transforms: proposal last(1) reserved(1) length(2) number(1)
  protocol(1) spi-size(1) transforms(1) spi; transform last(1) reserved(1)
  length(2) type(1) reserved(1) id(2) attributes. Transform type 1 is ENCR,
  2 PRF, 3 INTEG, 4 KE, 5 SN; the IANA registries give the ids, and 11 is
  ENCR_NULL with 0 INTEG NONE the two a downgrade wants.
* RFC 4187 8.1 -- EAP-AKA packet: Code(1) Identifier(1) Length(2) Type(1)=23
  Subtype(1) Reserved(2), then attributes of Type(1) Length(1, in 4-octet
  units) Value padded to 4 octets.
* RFC 4187 11 -- the subtypes and attribute types, shared with EAP-SIM, with
  RFC 9048 8.2 for AT_KDF_INPUT (23), AT_KDF (24) and AT_BIDDING (136).

Nothing here is taken from the module: the registries are the IANA/RFC rows,
the encoders are written from the clause text, and the module is driven through
its own command line. Wireshark (tshark) is the second implementation for the
frame layout; that section is skipped when it is not installed.

Run:  python3 tools/vowifi-oracle/check_vowifi_codec.py [--module PATH] [--negctl]
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

MODULE = "modules/36_vowifi.sh"
BASH = os.environ.get("BASH", "bash")
TSHARK = os.environ.get("TSHARK", "tshark")

CASES = 0
MISMATCHES = 0
NOTES = 0
QUIET = False


# ── the registries, from the clauses ────────────────────────────────────

PAYLOAD = {
    0: "none", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT",
    38: "CERTREQ", 39: "AUTH", 40: "Ni", 41: "N", 42: "D", 43: "V",
    44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 49: "GSPM",
    50: "IDg", 51: "GSA", 52: "KD", 53: "SKF", 54: "PS",
}
EXCHANGE = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL", 38: "IKE_SESSION_RESUME", 39: "GSA_AUTH",
    40: "GSA_REGISTRATION", 41: "GSA_REKEY", 42: "GSA_INBAND_REKEY",
    43: "IKE_INTERMEDIATE", 44: "IKE_FOLLOWUP_KE",
}
TRANSFORM_TYPE = {
    1: "Encryption Algorithm (ENCR)", 2: "Pseudo-random Function (PRF)",
    3: "Integrity Algorithm (INTEG)", 4: "Key Exchange Method (KE)",
    5: "Sequence Numbers (SN)", 6: "Additional Key Exchange 1 (ADDKE1)",
    7: "Additional Key Exchange 2 (ADDKE2)", 8: "Additional Key Exchange 3 (ADDKE3)",
    9: "Additional Key Exchange 4 (ADDKE4)", 10: "Additional Key Exchange 5 (ADDKE5)",
    11: "Additional Key Exchange 6 (ADDKE6)", 12: "Additional Key Exchange 7 (ADDKE7)",
    13: "Key Wrap Algorithm (KWA)",
    14: "Group Controller Authentication Method (GCAUTH)",
}
ID_TYPE = {
    1: "ID_IPV4_ADDR", 2: "ID_FQDN", 3: "ID_RFC822_ADDR", 5: "ID_IPV6_ADDR",
    9: "ID_DER_ASN1_DN", 10: "ID_DER_ASN1_GN", 11: "ID_KEY_ID",
    12: "ID_FC_NAME", 13: "ID_NULL",
}
EAP_SUBTYPE = {
    1: "AKA-Challenge", 2: "AKA-Authentication-Reject",
    4: "AKA-Synchronization-Failure", 5: "AKA-Identity", 10: "SIM-Start",
    11: "SIM-Challenge", 12: "AKA-Notification", 13: "AKA-Reauthentication",
    14: "AKA-Client-Error",
}
EAP_ATTR = {
    1: "AT_RAND", 2: "AT_AUTN", 3: "AT_RES", 4: "AT_AUTS", 6: "AT_PADDING",
    7: "AT_NONCE_MT", 10: "AT_PERMANENT_ID_REQ", 11: "AT_MAC",
    12: "AT_NOTIFICATION", 13: "AT_ANY_ID_REQ", 14: "AT_IDENTITY",
    15: "AT_VERSION_LIST", 16: "AT_SELECTED_VERSION", 17: "AT_FULLAUTH_ID_REQ",
    19: "AT_COUNTER", 20: "AT_COUNTER_TOO_SMALL", 21: "AT_NONCE_S",
    22: "AT_CLIENT_ERROR_CODE", 23: "AT_KDF_INPUT", 24: "AT_KDF",
    129: "AT_IV", 130: "AT_ENCR_DATA", 132: "AT_NEXT_PSEUDONYM",
    133: "AT_NEXT_REAUTH_ID", 134: "AT_CHECKCODE", 135: "AT_RESULT_IND",
    136: "AT_BIDDING",
}
ENCR = {
    1: "ENCR_DES_IV64", 2: "ENCR_DES", 3: "ENCR_3DES", 4: "ENCR_RC5",
    5: "ENCR_IDEA", 6: "ENCR_CAST", 7: "ENCR_BLOWFISH", 8: "ENCR_3IDEA",
    9: "ENCR_DES_IV32", 11: "ENCR_NULL", 12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR", 14: "ENCR_AES_CCM_8", 15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16", 18: "ENCR_AES_GCM_8", 19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16", 21: "ENCR_NULL_AUTH_AES_GMAC",
    23: "ENCR_CAMELLIA_CBC", 24: "ENCR_CAMELLIA_CTR",
    25: "ENCR_CAMELLIA_CCM_8", 26: "ENCR_CAMELLIA_CCM_12",
    27: "ENCR_CAMELLIA_CCM_16", 28: "ENCR_CHACHA20_POLY1305",
    29: "ENCR_AES_CCM_8_IIV", 30: "ENCR_AES_GCM_16_IIV",
    31: "ENCR_CHACHA20_POLY1305_IIV", 32: "ENCR_KUZNYECHIK_MGM_KTREE",
    33: "ENCR_MAGMA_MGM_KTREE", 34: "ENCR_KUZNYECHIK_MGM_MAC_KTREE",
    35: "ENCR_MAGMA_MGM_MAC_KTREE",
}
INTEG = {
    0: "NONE", 1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC", 4: "AUTH_KPDK_MD5", 5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128", 7: "AUTH_HMAC_SHA1_160", 8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC", 10: "AUTH_AES_192_GMAC", 11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}
PRF = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC", 5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512", 8: "PRF_AES128_CMAC", 9: "PRF_HMAC_STREEBOG_512",
}
KE = {
    1: "768-bit MODP Group", 2: "1024-bit MODP Group", 5: "1536-bit MODP Group",
    14: "2048-bit MODP Group", 15: "3072-bit MODP Group",
    16: "4096-bit MODP Group", 17: "6144-bit MODP Group",
    18: "8192-bit MODP Group", 19: "256-bit random ECP group",
    20: "384-bit random ECP group", 21: "521-bit random ECP group",
    22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
    23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
    24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
    25: "192-bit Random ECP Group", 26: "224-bit Random ECP Group",
    27: "brainpoolP224r1", 28: "brainpoolP256r1", 29: "brainpoolP384r1",
    30: "brainpoolP512r1", 31: "Curve25519", 32: "Curve448",
    33: "GOST3410_2012_256", 34: "GOST3410_2012_512",
    35: "ml-kem-512", 36: "ml-kem-768", 37: "ml-kem-1024",
}
ESN = {
    0: "32-bit Sequential Numbers",
    1: "Partially Transmitted 64-bit Sequential Numbers",
    2: "32-bit Unspecified Numbers",
}
# IANA "IKEv2 Notify Message Error Types" / "... Status Types" (RFC 7296,
# 4555, 5685, 5723, 5739, 5840, 5857, 5998, 6023, 6290, 6311, 6467, 6631,
# 6867, 7383, 7427, 7791, 8019, 8784, 8983, 9242, 9347, 9370, 9593, 9611,
# 9838, 9867); the Reserved and Unassigned rows are absent, so a value that is
# not named here is not named by the registry either.
NOTIFY_ERROR = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS",
    40: "UNACCEPTABLE_ADDRESSES", 41: "UNEXPECTED_NAT_DETECTED",
    42: "USE_ASSIGNED_HoA", 43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND", 45: "INVALID_GROUP_ID",
    46: "AUTHORIZATION_FAILED", 47: "STATE_NOT_FOUND", 48: "TS_MAX_QUEUE",
    49: "REGISTRATION_FAILED",
}
NOTIFY_STATUS = {
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE", 16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE", 16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED", 16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED", 16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS", 16399: "NO_ADDITIONAL_ADDRESSES",
    16400: "UPDATE_SA_ADDRESSES", 16401: "COOKIE2", 16402: "NO_NATS_ALLOWED",
    16403: "AUTH_LIFETIME", 16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS", 16406: "REDIRECT_SUPPORTED", 16407: "REDIRECT",
    16408: "REDIRECTED_FROM", 16409: "TICKET_LT_OPAQUE", 16410: "TICKET_REQUEST",
    16411: "TICKET_ACK", 16412: "TICKET_NACK", 16413: "TICKET_OPAQUE",
    16414: "LINK_ID", 16415: "USE_WESP_MODE", 16416: "ROHC_SUPPORTED",
    16417: "EAP_ONLY_AUTHENTICATION", 16418: "CHILDLESS_IKEV2_SUPPORTED",
    16419: "QUICK_CRASH_DETECTION", 16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
    16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED", 16422: "IKEV2_MESSAGE_ID_SYNC",
    16423: "IPSEC_REPLAY_COUNTER_SYNC", 16424: "SECURE_PASSWORD_METHODS",
    16425: "PSK_PERSIST", 16426: "PSK_CONFIRM", 16427: "ERX_SUPPORTED",
    16428: "IFOM_CAPABILITY", 16429: "GROUP_SENDER",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
    16432: "CLONE_IKE_SA_SUPPORTED", 16433: "CLONE_IKE_SA", 16434: "PUZZLE",
    16435: "USE_PPK", 16436: "PPK_IDENTITY", 16437: "NO_PPK_AUTH",
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED", 16439: "IP4_ALLOWED",
    16440: "IP6_ALLOWED", 16441: "ADDITIONAL_KEY_EXCHANGE", 16442: "USE_AGGFRAG",
    16443: "SUPPORTED_AUTH_METHODS", 16444: "SA_RESOURCE_INFO", 16445: "USE_PPK_INT",
    16446: "PPK_IDENTITY_KEY", 16447: "IKE_SA_INIT_FULL_TRANSCRIPT_AUTH",
}


# ── harness ─────────────────────────────────────────────────────────────

def run(module, *args):
    p = subprocess.run([BASH, module] + [str(a) for a in args],
                       capture_output=True, cwd=os.path.dirname(os.path.abspath(module)))
    mode = "r" if p.returncode == 0 else "e"
    # The column-1 keys are ASCII; the values can be arbitrary octets, and a
    # byte above 0x7F is not valid UTF-8. Decode as latin-1 to keep every
    # octet the module printed.
    return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")


def fld(out, key):
    for line in out.split("\n"):
        parts = line.split("\t")
        if parts and parts[0] == key:
            return parts[1] if len(parts) > 1 else ""
    return ""


def rows(out, prefix):
    return [l for l in out.split("\n") if l.startswith(prefix)]


def add(name, want, got):
    global CASES, MISMATCHES, QUIET
    CASES += 1
    CASES_LOG.append((name, want, got))
    if want != got:
        MISMATCHES += 1
        if not QUIET:
            print("MISMATCH\t%s\twant=%r\tgot=%r" % (name, want, got))


def ok(name, cond):
    add(name, True, bool(cond))


def hexb(b):
    return b.hex()


# ── encoders, from the clause text ─────────────────────────────────────

def ike_header(nextp, exch, flags, mid, body, ispi=b"\x11" * 8, rspi=b"\x00" * 8):
    """RFC 7296 3.1."""
    total = 28 + len(body)
    return (ispi + rspi + bytes([nextp, 0x20, exch, flags]) +
            struct.pack(">I", mid) + struct.pack(">I", total) + body)


def chain(items):
    """Wire a payload list: each payload's next-payload octet names the following type."""
    body = b""
    for i in range(len(items) - 1, -1, -1):
        nxt = items[i + 1][0] if i + 1 < len(items) else 0
        body = bytes([nxt, 0]) + struct.pack(">H", 4 + len(items[i][1])) + items[i][1] + body
    return body


def ike_msg(exch, flags, mid, items):
    """A whole message: the header's next-payload octet names the first payload."""
    return ike_header(items[0][0], exch, flags, mid, chain(items))


def payload(nextp, ptype, body, critical=False, length=None):
    """RFC 7296 3.2 (the type itself is not on the wire)."""
    flags = 0x80 if critical else 0x00
    n = 4 + len(body) if length is None else length
    return bytes([nextp, flags]) + struct.pack(">H", n) + body


def transform(ttype, tid, attrs=b"", last=True, length=None):
    """RFC 7296 3.3.2: last(1) reserved(1) length(2) type(1) reserved(1) id(2)."""
    n = 8 + len(attrs) if length is None else length
    return bytes([3 if last else 0, 0]) + struct.pack(">H", n) + \
        bytes([ttype, 0]) + struct.pack(">H", tid) + attrs


def proposal(pid, proto, transforms, spi=b"", last=True, length=None):
    """RFC 7296 3.3.1."""
    body = spi + b"".join(transforms)
    n = 8 + len(body) if length is None else length
    return bytes([2 if last else 0, 0]) + struct.pack(">H", n) + \
        bytes([pid, proto, len(spi), len(transforms)]) + body


def eap_attr(at, value):
    """RFC 4187 8.1: length in 4-octet units, value padded with zeros."""
    n = 2 + len(value)
    units = (n + 3) // 4
    return bytes([at, units]) + value + b"\x00" * (units * 4 - n)


def eap_aka(code, ident, subtype, attrs=b"", reserved=b"\x00\x00"):
    """RFC 4187 8.1."""
    total = 8 + len(attrs)
    return bytes([code, ident]) + struct.pack(">H", total) + \
        bytes([23, subtype]) + reserved + attrs


def parse_payloads(msg):
    """Walk the chain the way 3.2 says, returning rows for comparison."""
    out = []
    off = 28
    nt = msg[16]
    n = 1
    while nt != 0 and off + 4 <= len(msg):
        nxt = msg[off]
        pflags = msg[off + 1]
        plen = struct.unpack(">H", msg[off + 2:off + 4])[0]
        out.append((n, off, nt, PAYLOAD.get(nt, "unassigned"),
                    "yes" if pflags & 0x80 else "no", plen))
        if nt == 46:
            break
        off += plen
        nt = nxt
        n += 1
    return out


def pcap(path, pkt):
    """A classic pcap with one Ethernet packet, for tshark."""
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
    with open(path, "wb") as fh:
        fh.write(hdr + rec + pkt)


def ip_udp(payload, sport=500, dport=500):
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    s = 0
    for i in range(0, 20, 2):
        s += (ip[i] << 8) + ip[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    ip = ip[:10] + struct.pack(">H", (~s) & 0xFFFF) + ip[12:]
    return eth + ip + udp + payload


# ── sections ────────────────────────────────────────────────────────────

SECTIONS = {}


def section(fn):
    SECTIONS[fn.__name__.replace("check_", "")] = fn
    return fn


@section
def check_registries(module):
    """Sweep every registry value and compare with the clause's row."""
    # named lookups, one sweep per kind
    for kind, table, rng, missing, cli in [
            ("payload", PAYLOAD, range(0, 56), "unassigned", "--payload"),
            ("exchange", EXCHANGE, range(32, 46), "unassigned", None),
            ("transform", TRANSFORM_TYPE, range(0, 16), "unassigned", "--transform"),
            ("idtype", ID_TYPE, range(0, 15), "unassigned", "--id-type"),
            ("eap-subtype", EAP_SUBTYPE, range(0, 16), "unknown", None),
            ("eap-att", EAP_ATTR, list(range(0, 31)) + list(range(126, 140)), "unknown", "--eap-attr"),
            ("notify", NOTIFY_ERROR, range(0, 40), "unassigned", "--notify"),
            ("notify", NOTIFY_STATUS, range(16384, 16400), "unassigned", "--notify"),
            ("esn", ESN, range(0, 4), "unknown", "--esn"),
    ]:
        if cli is None:
            continue
        for v in rng:
            want = table.get(v, missing)
            got = run(module, cli, v)[1].strip()
            add("%s-%d" % (kind, v), want, got)
    # exchange types have no per-name verb; they are read out of the header
    for v in range(32, 46):
        msg = ike_header(0, v, 0x08, 0, b"")
        got = fld(run(module, "--ike-parse", msg.hex())[1], "exchange_name")
        add("exchange-%d" % v, EXCHANGE.get(v, "unassigned"), got)
    # transform ids: the classifier prints the name
    for v, want in ENCR.items():
        got = fld(run(module, "--encr", v)[1], "name")
        add("encr-%d" % v, want, got)
    for v, want in INTEG.items():
        got = fld(run(module, "--integrity", v)[1], "name")
        add("integ-%d" % v, want, got)
    for v, want in KE.items():
        got = fld(run(module, "--dh", v)[1], "name")
        add("ke-%d" % v, want, got)
    # prf names come through the registry table
    out = run(module, "--types", "prf")[1]
    reg = {}
    for line in out.split("\n"):
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "prf":
            reg[int(parts[1])] = parts[2]
    add("registry-prf", PRF, reg)


@section
def check_header(module):
    """RFC 7296 3.1: build, parse, and the refusals the clause requires."""
    cases = [
        (33, 34, 0x08, 0),
        (0, 35, 0x00, 7),
        (46, 37, 0x10, 0xFFFFFFFF),
        (39, 36, 0x20, 1),
        (33, 43, 0x08, 2),
    ]
    for nextp, exch, flags, mid in cases:
        want = hexb(ike_header(nextp, exch, flags, mid, b""))
        got = run(module, "--ike-build", "1111111111111111", "0000000000000000",
                  nextp, exch, flags, "%08x" % mid)[1].strip().lower()
        add("build-%d-%d-%02x" % (exch, nextp, flags), want, got)
        out = run(module, "--ike-parse", want)[1]
        add("parse-next-%d" % nextp, str(nextp), fld(out, "next_payload"))
        add("parse-next-name-%d" % nextp, PAYLOAD.get(nextp, "unassigned"),
            fld(out, "next_payload_name"))
        add("parse-exch-%d" % exch, str(exch), fld(out, "exchange_type"))
        add("parse-exch-name-%d" % exch, EXCHANGE.get(exch, "unassigned"),
            fld(out, "exchange_name"))
        add("parse-mid-%d" % mid, str(mid), fld(out, "message_id"))
        add("parse-init-%d" % exch, "yes" if flags & 0x08 else "no", fld(out, "initiator"))
        add("parse-resp-%d" % exch, "yes" if flags & 0x20 else "no", fld(out, "response"))
        add("parse-verflag-%d" % exch, "yes" if flags & 0x10 else "no", fld(out, "version_flag"))

    good = ike_header(33, 34, 0x08, 0, b"")
    # length field disagrees with the octets that arrived
    bad = good[:24] + struct.pack(">I", len(good) + 4)
    rc, out, _ = run(module, "--ike-parse", bad.hex())
    add("refuse-length", True, rc != 0 and "length_alert" in out)
    # a reserved flag bit (0x01) is not defined
    bad = good[:19] + bytes([0x09]) + good[20:]
    rc, out, _ = run(module, "--ike-parse", bad.hex())
    add("refuse-reserved-flag", True, rc != 0 and "flags_alert" in out)
    # major version 1 is IKEv1, not a version of this protocol
    bad = good[:17] + bytes([0x10]) + good[18:]
    rc, out, _ = run(module, "--ike-parse", bad.hex())
    add("refuse-version", True, rc != 0 and "version_alert" in out)
    # minor version alone is a note, not a refusal
    bad = good[:17] + bytes([0x21]) + good[18:]
    rc, out, _ = run(module, "--ike-parse", bad.hex())
    add("minor-version-ok", 0, rc)
    add("minor-version-row", "1", fld(out, "version_minor"))
    # a header shorter than 28 octets is not a message
    add("refuse-short", True, run(module, "--ike-parse", "0011")[0] != 0)
    add("refuse-badhex", 2, run(module, "--ike-parse", "zz")[0])


@section
def check_walk(module):
    """RFC 7296 3.2: the payload chain, its bounds and its encryped tail."""
    body = chain([(33, proposal(1, 1, [transform(1, 12)])),
                  (34, b"\x00\x00" + b"\x11" * 8),
                  (40, b"\x22" * 8)])
    msg = ike_header(33, 34, 0x08, 0, body)
    out = run(module, "--walk", msg.hex())[1]
    want = parse_payloads(msg)
    got = []
    for line in out.split("\n"):
        parts = line.split("\t")
        if len(parts) == 6 and parts[0].isdigit():
            got.append((int(parts[0]), int(parts[1]), int(parts[2]), parts[3],
                        parts[4], int(parts[5])))
    add("walk-rows", want, got)

    # an SK payload ends the visible chain
    body = chain([(33, b""), (46, b"\x33" * 8)])
    msg = ike_header(33, 35, 0x08, 1, body)
    out = run(module, "--walk", msg.hex())[1]
    add("walk-sk-stop", 1, len([l for l in out.split("\n")
                                if l.startswith("note\tSK payload")]))
    sk = [l.split("\t") for l in out.split("\n") if l.startswith("2\t")]
    add("walk-sk-name", "SK", sk[0][3] if sk else "")

    # a critical bit is reported, not ignored (3.2)
    crit = bytes([0, 0x80]) + struct.pack(">H", 4)
    msg = ike_header(33, 34, 0x08, 0, crit)
    out = run(module, "--walk", msg.hex())[1]
    row = [l.split("\t") for l in out.split("\n") if l.startswith("1\t")]
    add("walk-critical", "yes", row[0][4] if row else "")

    good = ike_header(33, 34, 0x08, 0, crit)
    # payload length below its own 4-octet header
    bad = good[:28] + bytes([0, 0]) + struct.pack(">H", 2)
    rc, _, _ = run(module, "--walk", bad.hex())
    add("walk-refuse-short-payload", True, rc != 0)
    # payload that runs past the message
    bad = good[:28] + bytes([0, 0]) + struct.pack(">H", 64)
    rc, _, _ = run(module, "--walk", bad.hex())
    add("walk-refuse-past-end", True, rc != 0)
    # message length field larger than the frame
    bad = good[:24] + struct.pack(">I", len(good) + 16)
    rc, _, _ = run(module, "--walk", bad.hex())
    add("walk-refuse-length", True, rc != 0)


@section
def check_eap(module):
    """RFC 4187 8.1/11: the 8-octet header, the registry and the attributes."""
    rand = eap_attr(1, bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    autn = eap_attr(2, bytes.fromhex("101112131415161718191a1b1c1d1e1f"))
    mac = eap_attr(11, bytes.fromhex("202122232425262728292a2b2c2d2e2f"))
    attrs = rand + autn + mac
    want = eap_aka(1, 7, 1, attrs)
    got = run(module, "--eap-build", 1, 7, 1, attrs.hex())[1].strip().lower()
    add("eap-build", hexb(want), got)
    out = run(module, "--eap-parse", want.hex())[1]
    add("eap-code", "1", fld(out, "code"))
    add("eap-code-name", "Request", fld(out, "code_name"))
    add("eap-id", "7", fld(out, "id"))
    add("eap-length", str(len(want)), fld(out, "length"))
    add("eap-type", "23", fld(out, "type"))
    add("eap-subtype", "1", fld(out, "subtype"))
    add("eap-subtype-name", "AKA-Challenge", fld(out, "subtype_name"))
    add("eap-reserved", "0x0000", fld(out, "reserved"))
    add("eap-att-count", 3, len([l for l in out.split("\n")
                                if re.match(r"att\.\d+\.name\t", l)]))
    add("eap-att0-name", "AT_RAND", fld(out, "att.0.name"))
    add("eap-att0-value", "000102030405060708090a0b0c0d0e0f", fld(out, "att.0.value"))
    add("eap-att0-length", "20", fld(out, "att.0.length"))
    add("eap-att1-name", "AT_AUTN", fld(out, "att.1.name"))
    add("eap-att2-name", "AT_MAC", fld(out, "att.2.name"))
    add("eap-att2-value", "202122232425262728292a2b2c2d2e2f", fld(out, "att.2.value"))

    # each subtype name comes from the clause's registry
    for sub, name in EAP_SUBTYPE.items():
        pkt = eap_aka(1, 1, sub)
        out = run(module, "--eap-parse", pkt.hex())[1]
        add("eap-sub-%d" % sub, name, fld(out, "subtype_name"))

    # AT_KDF is one 4-octet unit (RFC 9048 3.2)
    kdf = eap_aka(1, 1, 1, eap_attr(24, b"\x00\x01"))
    out = run(module, "--eap-parse", kdf.hex())[1]
    add("eap-kdf", "AT_KDF", fld(out, "att.0.name"))
    add("eap-kdf-value", "0001", fld(out, "att.0.value"))

    # refusals: wrong type, an attribute that overruns, a fixed size violated
    add("eap-refuse-type", True,
        run(module, "--eap-parse", eap_aka(1, 1, 1).replace(b"\x17\x01", b"\x05\x01", 1).hex())[0] != 0)
    bad = eap_aka(1, 1, 1, bytes([11, 9]) + b"\x00" * 4)
    add("eap-refuse-overrun", True, run(module, "--eap-parse", bad.hex())[0] != 0)
    bad = eap_aka(1, 1, 1, bytes([11, 2]) + b"\x00" * 6)
    add("eap-refuse-mac-size", True, run(module, "--eap-parse", bad.hex())[0] != 0)
    bad = eap_aka(1, 1, 1, bytes([24, 3]) + b"\x00" * 10)
    add("eap-refuse-kdf-size", True, run(module, "--eap-parse", bad.hex())[0] != 0)
    bad = eap_aka(1, 1, 1, bytes([1, 0]))
    add("eap-refuse-zero-unit", True, run(module, "--eap-parse", bad.hex())[0] != 0)
    # length field that disagrees with the octets arrived
    bad = eap_aka(1, 1, 1)
    bad = bad[:2] + struct.pack(">H", len(bad) + 8) + bad[4:]
    rc, out, _ = run(module, "--eap-parse", bad.hex())
    add("eap-refuse-length", True, rc != 0 and "length_alert" in out)
    # the reserved octets are zero (8.1)
    bad = eap_aka(1, 1, 1, reserved=b"\x00\x01")
    rc, out, _ = run(module, "--eap-parse", bad.hex())
    add("eap-refuse-reserved", True, rc != 0 and "reserved_alert" in out)
    # a builder that is handed unaligned attributes says so
    add("eap-refuse-unaligned", 2,
        run(module, "--eap-build", 1, 1, 1, "010203")[0])


@section
def check_sa(module):
    """RFC 7296 3.3.1/3.3.2: proposals, transforms and the downgrade test."""
    clean = proposal(1, 1, [transform(1, 12), transform(3, 12)])
    out = run(module, "--null-check", clean.hex())[1]
    add("sa-proposal-number", "1", fld(out, "proposal.0.number"))
    add("sa-proposal-protocol", "1", fld(out, "proposal.0.protocol"))
    add("sa-proposal-transforms", "2", fld(out, "proposal.0.transforms"))
    add("sa-t0-name", "ENCR_AES_CBC", fld(out, "proposal.0.transform.0.name"))
    add("sa-t1-name", "AUTH_HMAC_SHA2_256_128", fld(out, "proposal.0.transform.1.name"))
    add("sa-clean-verdict", "no NULL encryption or INTEG NONE offered", fld(out, "tunnel_verdict"))

    null_encr = proposal(1, 1, [transform(1, 11)])
    out = run(module, "--null-check", null_encr.hex())[1]
    add("sa-null-encr", "ENCR_NULL", fld(out, "proposal.0.transform.0.name"))
    add("sa-null-encr-flag", 1, len(rows(out, "null_transform")))

    null_integ = proposal(1, 1, [transform(1, 12), transform(3, 0)])
    out = run(module, "--null-check", null_integ.hex())[1]
    add("sa-null-integ", "NONE", fld(out, "proposal.0.transform.1.name"))
    add("sa-null-integ-flag", 1, len(rows(out, "null_transform")))

    # a proposal that announces more transforms than it carries
    bad = proposal(1, 1, [transform(1, 12)])
    bad = bad[:7] + bytes([2]) + bad[8:]
    add("sa-refuse-transforms", True, run(module, "--null-check", bad.hex())[0] != 0)
    # a proposal length past the payload
    bad = proposal(1, 1, [transform(1, 12)], length=0xFF)
    add("sa-refuse-length", True, run(module, "--null-check", bad.hex())[0] != 0)


def frames_text(path):
    """Dissect every frame in the capture; return one text blob per frame."""
    text = subprocess.run([TSHARK, "-r", path, "-V"],
                          capture_output=True, text=True).stdout
    return re.split(r"\n(?=Frame \d+:)", text)


def pcap_multi(path, msgs):
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    with open(path, "wb") as fh:
        fh.write(hdr)
        for m in msgs:
            d = ip_udp(m)
            fh.write(struct.pack("<IIII", 0, 0, len(d), len(d)) + d)


def top_payload_types(text):
    """The visible payload chain: 4-space lines, one per payload (3.2)."""
    return [int(x) for x in re.findall(r"^    Payload: [^\n]*\((\d+)\)(?: # ?\d+)?$", text, re.M)]


# Wireshark 4.2.2 carries an older copy of two rows: 16429 was renamed
# SENDER_REQUEST_ID -> GROUP_SENDER by RFC 9838, ID type 12 FC_NAME is still
# KEY_LIST there, and 13 is still "Future use". The numbers are the same; the
# names are checked against the registry table, not against this dissector.
DRIFT_NAMES = {
    ("notify", 16429): "SENDER_REQUEST_ID",
    ("notify", 46): "CHILD_SA_NOT_FOUND",
    ("prf", 4): "PRF_AES128_CBC",
    ("prf", 8): "PRF_AES128_CMAC6",
    ("idtype", 12): "KEY_LIST",
    ("idtype", 13): "Future use",
}


@section
def check_tshark(module):
    """The second implementation: Wireshark's IKEv2 dissector."""
    if not shutil.which(TSHARK):
        print("NOTE\tno tshark; the dissector comparison is skipped")
        return
    d = tempfile.mkdtemp(prefix="vowi")
    try:
        frames = [
            ("sa_init", 34, 0x08, 0,
             [(33, proposal(1, 1, [transform(1, 12)])),
              (34, b"\x00\x00" + b"\x11" * 8),
              (40, b"\x22" * 8)]),
            ("ike_auth", 35, 0x08, 1,
             [(35, b"\x02" + b"\x01" * 4 + b"\x00" * 8),
              (39, b"\x00" + b"\x02" * 4 + b"\x00" * 8),
              (33, proposal(1, 3, [transform(1, 11)])),
              (44, b"\x04\x00\x00\x00\x00\x00"),
              (45, b"\x04\x00\x00\x00\x00\x00")]),
            ("eap", 35, 0x08, 2,
             [(48, eap_aka(1, 9, 1, eap_attr(1, bytes.fromhex("00" * 16)) +
                                      eap_attr(11, bytes.fromhex("00" * 16))))]),
        ]
        path = os.path.join(d, "chain.pcap")
        pcap_multi(path, [ike_msg(ex, fl, mi, items) for _, ex, fl, mi, items in frames])
        texts = frames_text(path)
        for (name, exch, flags, mid, items), text in zip(frames, texts):
            msg = ike_msg(exch, flags, mid, items)
            m = re.search(r"Exchange type: .*\((\d+)\)", text)
            add("tshark-%s-exchange" % name, exch, int(m.group(1)) if m else -1)
            mod = run(module, "--walk", msg.hex())[1]
            mine = [int(l.split("\t")[2]) for l in mod.split("\n")
                    if len(l.split("\t")) == 6 and l.split("\t")[0].isdigit()]
            add("tshark-%s-chain" % name, mine, top_payload_types(text))
            if name == "eap":
                sm = re.search(r"EAP-AKA Subtype: (.+?) \((\d+)\)", text)
                add("tshark-eap-subtype-number", 1, int(sm.group(2)) if sm else -1)
                eaphex = items[0][1].hex()
                add("tshark-eap-subtype-name",
                    fld(run(module, "--eap-parse", eaphex)[1], "subtype_name"),
                    sm.group(1) if sm else "?")
                diss = re.findall(r"EAP-AKA Attribute: (.+?) \((\d+)\)", text)
                mine_attrs = [l.split("\t")[1] for l in
                              run(module, "--eap-parse", eaphex)[1].split("\n")
                              if re.match(r"att\.\d+\.name\t", l)]
                add("tshark-eap-attrs", [n for n, _ in diss], mine_attrs)

        # Every registry row the dissector names: one frame per value. The
        # module's value->name map against Wireshark's, where both use the
        # registry's token; narrative spellings ("AES-GCM with a 12 octet
        # ICV", "Unknown") are not a disagreement about the number, so they
        # are counted and skipped instead of compared.
        skipped = [0]

        def norm(v):
            return re.sub(r"[^a-z0-9]+", " ", v.lower()).strip()

        def token(v):
            return bool(re.fullmatch(r"[A-Za-z0-9_\-]+", v))

        def drift_named(kind, value, got):
            """The dissector's table can predate the registry row."""
            return DRIFT_NAMES.get((kind, value)) == got

        def drift(got):
            g = got.lower()
            return (not got or g == "unknown" or g.startswith("reserved")
                    or g.startswith("future use"))

        def compare(kind, value, want, got):
            if drift(got) or drift_named(kind, value, got):
                skipped[0] += 1
                return
            if token(want) and token(got):
                add("tshark-%s-%d" % (kind, value), norm(want), norm(got))
            else:
                skipped[0] += 1

        def sweep(kind, values, msg_of, pattern, want_of):
            path = os.path.join(d, kind + ".pcap")
            pcap_multi(path, [msg_of(v) for v in values])
            for v, text in zip(values, frames_text(path)):
                m = re.search(pattern, text)
                compare(kind, v, want_of(v), m.group(1) if m else "")

        def sa(ttype, tid):
            return ike_msg(34, 0x08, 0, [(33, proposal(1, 1, [transform(ttype, tid)]))])

        sweep("encr", sorted(ENCR), lambda v: sa(1, v),
              r"Transform ID \(ENCR\): (.+?) \(\d+\)", lambda v: ENCR[v])
        sweep("integ", sorted(INTEG), lambda v: sa(3, v),
              r"Transform ID \(INTEG\): (.+?) \(\d+\)", lambda v: INTEG[v])
        sweep("prf", sorted(PRF), lambda v: sa(2, v),
              r"Transform ID \(PRF\): (.+?) \(\d+\)", lambda v: PRF[v])
        sweep("ke", sorted(KE), lambda v: sa(4, v),
              r"Transform ID \(D-H\): (.+?) \(\d+\)", lambda v: KE[v])

        def notify_msg(v):
            return ike_msg(37, 0x08, 0, [(41, bytes([0, 0]) + struct.pack(">H", v))])
        notify_rows = ([(v, NOTIFY_ERROR[v]) for v in sorted(NOTIFY_ERROR)] +
                       [(v, NOTIFY_STATUS[v]) for v in sorted(NOTIFY_STATUS)])
        path = os.path.join(d, "notify.pcap")
        pcap_multi(path, [notify_msg(v) for v, _ in notify_rows])
        for (v, want), text in zip(notify_rows, frames_text(path)):
            m = re.search(r"Notify Message Type: (.+?) \(\d+\)", text)
            got = m.group(1) if m else ""
            if drift(got) or drift_named("notify", v, got):
                skipped[0] += 1
            else:
                add("tshark-notify-%d" % v, want, got)

        id_rows = sorted(ID_TYPE)
        path = os.path.join(d, "idtype.pcap")
        pcap_multi(path, [ike_msg(35, 0x08, 0,
                                 [(35, bytes([v, 0, 0, 0]) + b"\x01")]) for v in id_rows])
        for v, text in zip(id_rows, frames_text(path)):
            m = re.search(r"ID type: (.+?) \(\d+\)", text)
            got = (m.group(1) if m else "").replace("ID_", "")
            if drift(got) or ("idtype", v) in DRIFT_NAMES:
                skipped[0] += 1
            else:
                add("tshark-idtype-%d" % v, ID_TYPE[v][3:], got)

        if skipped[0]:
            print("NOTE\ttshark leaves %d registry row(s) unnamed or uses a "
                  "narrative spelling; those rows are checked against the "
                  "registry table above instead" % skipped[0])
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── mutation controls ──────────────────────────────────────────────────

MUTANTS = [
    ("payload-41-invented",
     "payload\t41\tN",
     "payload\t41\tNr",
     ["walk", "header", "registries"]),
    ("payload-46-renamed",
     "payload\t46\tSK",
     "payload\t46\tTSr",
     ["walk", "registries"]),
    ("eap-subtype-2-renamed",
     "eap-subtype\t2\tAKA-Authentication-Reject",
     "eap-subtype\t2\tAKA-Authentication-Response",
     ["eap"]),
    ("header-length-unchecked",
     '    (( len == frame )) || { printf \'length_alert\\tlength field %d but %d octets arrived\\n\' "$len" "$frame"; rc=1; }',
     '    (( 1 )) || { printf \'length_alert\\tlength field %d but %d octets arrived\\n\' "$len" "$frame"; rc=1; }',
     ["header"]),
    ("sk-no-longer-ends-the-walk",
     "        (( nt == 46 )) && { printf 'note\\tSK payload: the chain continues encrypted\\n'; return 0; }",
     "        (( 0 )) && { printf 'note\\tSK payload: the chain continues encrypted\\n'; return 0; }",
     ["walk"]),
    ("eap-mac-size-unchecked",
     '            1|2|11) (( abytes == 20 )) || {',
     '            1|2|11) (( 1 )) || {',
     ["eap"]),
    ("null-encryption-scored-clean",
     "                1:11|1:21) printf 'null_transform\\tproposal %d offers %s\\n' \"$pid\" \"$tname\"; found=$(( found + 1 )) ;;",
     "                1:11|1:21) : ;;",
     ["sa"]),
]


def run_mutant(module, anchor, repl, sections):
    with open(module, encoding="utf-8") as fh:
        src = fh.read()
    if src.count(anchor) < 1:
        return "ANCHOR-MISSING", []
    tmp = os.path.join(tempfile.mkdtemp(prefix="vowimut"), "mutant.sh")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(src.replace(anchor, repl, 1))
    os.chmod(tmp, 0o755)
    start = len(CASES_LOG)
    global QUIET
    QUIET = True
    try:
        check_all(tmp, only=sections)
    finally:
        QUIET = False
    fails = [c[0] for c in CASES_LOG[start:] if c[1] != c[2]]
    return ("CAUGHT" if fails else "SURVIVED"), fails


def negctl(module):
    caught = 0
    for name, anchor, repl, sections in MUTANTS:
        verdict, fails = run_mutant(module, anchor, repl, sections)
        print("NEGCTL\t" + name + "\t" + verdict)
        if verdict == "CAUGHT":
            caught += 1
            print("NEGCTL-CASE\t" + name + "\t" + fails[0])
        elif verdict == "ANCHOR-MISSING":
            print("NEGCTL-ANCHOR\t" + name + "\tthe anchor text is not in the module")
        else:
            print("NEGCTL-MISS\t" + name + "\tevery case in " + ",".join(sections) + " still passed")
    print("NEGCTL-CAUGHT\t%d of %d" % (caught, len(MUTANTS)))
    return 0 if caught == len(MUTANTS) else 1


# ── driver ──────────────────────────────────────────────────────────────

CASES_LOG = []


def check_all(module, only=None):
    for key, fn in SECTIONS.items():
        if only is not None and key not in only:
            continue
        fn(module)


def report():
    print("CASES\t%d" % CASES)
    print("MISMATCHES\t%d" % MISMATCHES)
    print("RESULT\t%s" % ("PASS" if MISMATCHES == 0 else "FAIL"))
    return 0 if MISMATCHES == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=MODULE)
    ap.add_argument("--negctl", action="store_true")
    ap.add_argument("--only", default="")
    args = ap.parse_args(argv)
    module = args.module
    if not os.path.isabs(module):
        here = os.path.dirname(os.path.abspath(__file__))
        module = os.path.normpath(os.path.join(here, "..", "..", args.module))
    if not os.path.exists(module):
        print("ERROR\tno module at " + module)
        return 2
    only = [s for s in args.only.split(",") if s]
    check_all(module, only=only or None)
    rc = report()
    if args.negctl:
        rc = max(rc, negctl(module))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
