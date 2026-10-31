#!/usr/bin/env python3
"""GTP fuzz corpus generator -- the generator half of `11_lte_core --gtp-fuzz`.

What this is not: a sender.  Run with no flags it prints a plan -- one row per
case naming the field it moves, the clause that decides the answer, and the
octets that would go on the wire -- and transmits nothing.  Only `--transmit`
puts a datagram on a socket, and the module reaches this tool with that flag
from the one verb whose name says it sends.

Every case varies exactly one field away from a well-formed message that the
same module already builds, so a case that a stack accepts, or a case that
crashes one, is attributable to that field and not to a pile of edits.  The
constants are cited where they are used:

  TS 29.281 5.1      GTP-U header: version, PT, spare, E/S/PN, type, length, TEID
  TS 29.281 5.2.1    extension headers: length octet, content, next-type octet
  TS 29.281 5.2.2    the extension-type table (0x00 ends a chain, 0x85 is PDU
                     Session Container, 0x40 is UDP Port, 0x01 is a service class
                     indicator)
  TS 29.281 7.1      Echo Request/Response: length 4 when no extension follows
  TS 29.281 7.3      Error Indication: the answer to a datagram for no tunnel
  TS 29.274 5.1      GTPv2-C header: version 2, P, T, spare, type, length, TEID,
                     sequence number, spare octet
  TS 29.274 5.5.1    an IE whose criticality is "reject" and is unknown
  TS 29.274 8.2      information element table: shapes and fixed lengths
  TS 29.274 8.3      IMSI: two digits per octet, length 8, odd last digit padded
  TS 29.060 6.1      GTPv1-C header and its optional sequence/N-PDU/next-type

The corpus is a function of the seed and nothing else: two runs with the same
seed produce the same octets, so a case that found something can be replayed by
number rather than by luck.
"""

import argparse
import os
import random
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# constants, each with the clause that fixes it
# ---------------------------------------------------------------------------

# TS 29.281 5.1: bits 8-6 version (1), bit 5 PT (1), bit 4 spare, bit 3 E,
# bit 2 S, bit 1 PN, bit 0 spare.  Version 1 with PT set is 0x30, and with E
# set 0x34.  The message type is a separate octet: a G-PDU is type 255
# (TS 29.281 7.3), not 0x30 -- mixing the two is what a dissector catches first.
GTPU_FLAGS = 0x30
GTPU_GPDU = 0xFF
GTPU_FLAG_E = 0x04
GTPU_FLAG_S = 0x02
GTPU_FLAG_PN = 0x01

# TS 29.281 7.1: Echo Request is type 1, Echo Response 2, Error Indication 26.
GTPU_ECHO_REQUEST = 0x01
GTPU_ERROR_INDICATION = 0x1A

# TS 29.281 5.2.2: the extension-type table.
EXT_NO_MORE = 0x00
EXT_UDP_PORT = 0x40
EXT_PDU_SESSION_CONTAINER = 0x85
EXT_SERVICE_CLASS = 0x01

# TS 29.274 5.1: version 2 occupies bits 8-6 (0x40), P is bit 4 (0x10),
# T is bit 3 (0x08).  A v2-C message with both flags set is 0x48.
GTPC2_V2 = 0x40
GTPC2_FLAG_P = 0x10
GTPC2_FLAG_T = 0x08

# TS 29.274 8.2 / 8.3: the IE type numbers this corpus moves.
IE_IMSI = 1
IE_CAUSE = 2
IE_EPS_BEARER_ID = 73
IE_F_TEID = 87
IE_BEARER_CONTEXT = 93

# TS 29.274 8.3: the IMSI IE's length is 8 (odd last digit padded with 0xF).
IMSI_OCTETS = 8

# TS 29.060 6.1: version 1 in bits 8-6 (0x20), PT is bit 4 (0x10), then the
# spare, E, S, PN bits as in GTP-U.
GTPC1_FLAG_V1_PT = 0x30


def gtp_u(message_type, teid, payload=b"", flags=GTPU_FLAGS, length=None,
          seq=None, npdu=0, next_ext=0):
    """A GTP-U header (TS 29.281 5.1).

    The length field counts everything after the mandatory eight octets: for a
    G-PDU that is the payload alone, and for a message with S or PN set it also
    counts the sequence number, N-PDU and next-extension-type octets.
    """
    tail = payload
    if seq is not None:
        tail = struct.pack("!HBB", seq, npdu, next_ext) + payload
    if length is None:
        length = len(tail)
    return struct.pack("!BBH I", flags, message_type, length & 0xFFFF,
                       teid & 0xFFFFFFFF) + tail


def gtp_c2(message_type, teid, seq, ies=b"", flags=None, length=None):
    """A GTPv2-C header (TS 29.274 5.1).

    Octets 1-4 are mandatory.  The T flag decides whether the four TEID octets
    are there at all: with T clear the message goes straight to the sequence
    number, which is what modules/11_lte_core.sh's own builder does
    (lcore_gtpc_msg counts four octets for the tail only when T is set) and
    what a dissector reads back.  The length field counts everything after the
    four mandatory octets.
    """
    if flags is None:
        flags = GTPC2_V2 | (GTPC2_FLAG_T if teid else 0)
    body = b""
    if flags & GTPC2_FLAG_T:
        body += struct.pack("!I", teid & 0xFFFFFFFF)
    body += struct.pack("!I", seq & 0xFFFFFF)[1:] + b"\x00"
    body += ies
    if length is None:
        length = len(body)
    return struct.pack("!BBH", flags, message_type, length & 0xFFFF) + body


def gtp_c1(message_type, teid, payload=b"", flags=None, length=None, seq=None,
           npdu=0, next_ext=0):
    """A GTPv1-C header (TS 29.060 6.1): V1/PT, type, length, TEID, options."""
    if flags is None:
        flags = GTPC1_FLAG_V1_PT | (GTPU_FLAG_S if seq is not None else 0)
    tail = payload
    if seq is not None:
        # TS 29.060 6.1: the sequence number is two octets here, followed by
        # N-PDU and next-extension-type -- four octets, a multiple of four.
        tail = struct.pack("!HBB", seq, npdu, next_ext) + payload
    if length is None:
        length = len(tail)
    return struct.pack("!BBH I", flags, message_type, length & 0xFFFF,
                       teid & 0xFFFFFFFF) + tail


def ie(ie_type, payload, criticality=0, instance=0, length=None):
    """A GTPv2-C information element (TS 29.274 8.1).

    Octet 0 is the type -- ONE octet, not two -- octets 1-2 are the length of
    the value alone, and octet 3 carries criticality in bits 7-5 and the
    instance in bits 3-0, then the value.  A two-octet type here reads every IE
    one octet short, which a dissector reports as an IE length of 256.

    The module's own walker (lcore_gtpc_parse_ies in modules/11_lte_core.sh)
    states the same shape at its head, and tshark 4.2.2 agrees with it.
    """
    if length is None:
        length = len(payload)
    return (bytes([ie_type & 0xFF]) + struct.pack("!H", length & 0xFFFF)
            + bytes([((criticality & 0x7) << 5) | (instance & 0x0F)]) + payload)


def imsi_value(digits):
    """TS 29.274 8.3 (TBCD, as TS 24.008 9.1.2.2 defines it).

    Two digits per octet and the LOW nibble holds the first digit; an odd
    number of digits ends with the filler 1111 in the high nibble of the last
    octet.  Writing the first digit high instead produces a well-formed IMSI
    that names a different subscriber -- which is why a dissector reads the
    swapped value back rather than complaining.
    """
    out = bytearray()
    padded = digits + ("F" if len(digits) % 2 else "")
    for i in range(0, len(padded), 2):
        out.append(int(padded[i], 16) | (int(padded[i + 1], 16) << 4))
    return bytes(out)


def _clear_t(message):
    """Clear the T flag (TS 29.274 5.1) without moving any other octet."""
    out = bytearray(message)
    out[0] &= ~GTPC2_FLAG_T
    return bytes(out)


def _spare_octet(message):
    """Set octet 11 -- the spare octet of TS 29.274 5.1 -- to 0xFF."""
    out = bytearray(message)
    if len(out) > 11:
        out[11] = 0xFF
    return bytes(out)


def ext_header(content, next_type=EXT_NO_MORE, length=None):
    """An extension header (TS 29.281 5.2.1).

    The length octet carries n-1, where n counts four-octet blocks, and the
    header is n blocks long: length (1), content (4n-2), next-type (1).  So the
    content of a one-block header is exactly two octets, and content of any
    other size is padded to fit -- a five-octet header would not be one.
    """
    if length is None:
        blocks = max(1, (len(content) + 2 + 3) // 4)
        content = content + bytes(blocks * 4 - 2 - len(content))
        length = blocks - 1
    return bytes([length]) + content + bytes([next_type])


# ---------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------

def build_cases(seed):
    """Every case, in a fixed order; the seed moves values, never the shapes."""
    rng = random.Random(seed)
    # A seeded TEID and sequence, so the same seed replays the same octets but
    # the corpus is not one hard-coded constant somebody could special-case.
    teid = rng.randrange(1, 0xFFFFFFFF)
    seq = rng.randrange(1, 0xFFFFFF)
    # TS 29.281 5.1: GTP-U's sequence number is two octets, and so is GTPv1-C's
    # (TS 29.060 6.1); only GTPv2-C has three (TS 29.274 5.1).
    seq16 = rng.randrange(1, 0xFFFF)
    imsi = "310150%09d" % (rng.randrange(0, 1000000000),)
    payload = bytes(rng.randrange(0, 256) for _ in range(6))
    cases = []

    def add(name, family, varies, clause, must, packet, port):
        cases.append({
            "case": name, "family": family, "varies": varies,
            "clause": clause, "must": must, "hex": packet.hex(),
            "port": port, "octets": len(packet),
        })

    # ── GTP-U header fields (TS 29.281 5.1) ────────────────────────────
    add("gtpu-control", "gtpu",
        "nothing (the control): version 1, PT set, length agrees with the data",
        "TS 29.281 5.1 / 7.3",
        "deliver the six payload octets to the tunnel named by the TEID, which "
        "is the only case in this family that must reach a payload sink",
        gtp_u(GTPU_GPDU, teid, payload), 2152)

    add("gtpu-version-2", "gtpu", "version in octet 1 (2 instead of 1)",
        "TS 29.281 5.1",
        "discard: a version this node does not implement has no parse, and "
        "answering it invites an amplification loop",
        gtp_u(GTPU_GPDU, teid, payload, flags=(0x40 | GTPU_FLAGS)), 2152)

    add("gtpu-pt-zero", "gtpu", "PT bit in octet 1 (0 instead of 1)",
        "TS 29.281 5.1",
        "do not read as GTP-U: PT=0 marks GTP' (charging), a different protocol "
        "with the same framing",
        gtp_u(GTPU_GPDU, teid, payload, flags=(GTPU_FLAGS & ~0x10)), 2152)

    add("gtpu-length-short", "gtpu", "length field (shorter than the datagram)",
        "TS 29.281 5.1",
        "parse by the length field and ignore the trailing octets; a receiver "
        "that trusts the datagram size reads payload as header",
        gtp_u(GTPU_GPDU, teid, payload, length=max(len(payload) - 2, 0)), 2152)

    add("gtpu-length-long", "gtpu", "length field (longer than the datagram)",
        "TS 29.281 5.1",
        "discard as malformed: the field promises octets that did not arrive, "
        "so the payload cannot be delivered whole",
        gtp_u(GTPU_GPDU, teid, payload, length=len(payload) + 16), 2152)

    add("gtpu-length-counts-eight", "gtpu",
        "length field (counts the mandatory header too)",
        "TS 29.281 5.1",
        "discard: the field excludes the eight mandatory octets, and a sender "
        "that includes them makes every following octet off by eight",
        gtp_u(GTPU_GPDU, teid, payload, length=len(payload) + 8), 2152)

    add("gtpu-teid-zero", "gtpu", "TEID (zero in a G-PDU)",
        "TS 29.281 5.1 / 7.3",
        "no tunnel exists for TEID 0, so the answer is Error Indication or a "
        "silent discard -- never delivery to a default tunnel",
        gtp_u(GTPU_GPDU, 0, payload), 2152)

    add("gtpu-sn-flag-no-sequence", "gtpu",
        "S bit with a length that leaves no room for the sequence number",
        "TS 29.281 5.1",
        "do not read a sequence number that is not there; the flag and the "
        "length field disagree and the length field wins",
        gtp_u(GTPU_GPDU, teid, b"", flags=GTPU_FLAGS | GTPU_FLAG_S,
              length=0, seq=None), 2152)

    add("gtpu-type-reserved", "gtpu", "message type (0x40, unassigned)",
        "TS 29.281 7.1",
        "discard or answer Error Indication: an unassigned type has no defined "
        "body, so nothing can be done with it",
        gtp_u(0x40, teid, payload), 2152)

    # ── GTP-U echo (TS 29.281 7.1) ─────────────────────────────────────
    add("gtpu-echo-length-8", "gtpu",
        "Echo Request length (twelve instead of eight): eight octets follow a "
        "chain whose first next-type is already 0x00",
        "TS 29.281 7.1 / 5.2.1",
        "discard or ignore the trailing octets: the chain says it ended, and "
        "Echo has no payload to put them in",
        gtp_u(GTPU_ECHO_REQUEST, teid, b"\x00" * 8,
              flags=GTPU_FLAGS | GTPU_FLAG_E, seq=seq16,
              next_ext=EXT_NO_MORE), 2152)

    add("gtpu-echo-no-flags", "gtpu",
        "Echo Request with E clear and four octets of body",
        "TS 29.281 7.1",
        "discard: four octets that are not announced as a sequence number are "
        "not part of an Echo, which is the only message with no payload",
        gtp_u(GTPU_ECHO_REQUEST, teid, struct.pack("!HBB", seq16, 0, 0),
              flags=GTPU_FLAGS), 2152)

    # ── extension chains (TS 29.281 5.2.1, 5.2.2) ──────────────────────
    add("gtpu-ext-honest", "gtpu",
        "nothing (the control): one one-block service-class header, 0x00 next",
        "TS 29.281 5.2.1 / 5.2.2",
        "walk the header, then stop at next-type 0x00; this case exists so the "
        "malformed chains below have a baseline in the same capture",
        gtp_u(GTPU_GPDU, teid,
              ext_header(b"\x15\xb3\x00\x00\x00\x00", next_type=EXT_NO_MORE),
              flags=GTPU_FLAGS | GTPU_FLAG_E, seq=seq16,
              next_ext=EXT_UDP_PORT), 2152)

    add("gtpu-ext-truncated-chain", "gtpu",
        "next-type of the only extension header (0xC3, an unassigned type, "
        "with no header after it)",
        "TS 29.281 5.2.2",
        "report a truncated chain: only 0x00 ends a chain, so a type that is "
        "not 0x00 with no octets left is a message that lies about its own end",
        gtp_u(GTPU_GPDU, teid,
              ext_header(b"\x15\xb3\x00\x00\x00\x00", next_type=0xC3),
              flags=GTPU_FLAGS | GTPU_FLAG_E, seq=seq16,
              next_ext=EXT_UDP_PORT), 2152)

    add("gtpu-ext-length-overrun", "gtpu",
        "length octet of the extension header (claims three blocks)",
        "TS 29.281 5.2.1",
        "stop at the datagram boundary and report the overrun; a chain that "
        "walks past the end reads another process's memory",
        gtp_u(GTPU_GPDU, teid,
              ext_header(b"\x15\xb3\x00\x00\x00", length=3),
              flags=GTPU_FLAGS | GTPU_FLAG_E, seq=seq16,
              next_ext=EXT_UDP_PORT), 2152)

    add("gtpu-ext-loop", "gtpu",
        "next-type chain (0x40 points at itself)",
        "TS 29.281 5.2.2",
        "bound the walk: the same type may repeat, so the limit is the "
        "datagram, not the chain",
        gtp_u(GTPU_GPDU, teid,
              ext_header(b"\x15\xb3\x00\x00\x00\x00",
                         next_type=EXT_UDP_PORT) * 3,
              flags=GTPU_FLAGS | GTPU_FLAG_E, seq=seq16,
              next_ext=EXT_UDP_PORT), 2152)

    # ── GTPv2-C header fields (TS 29.274 5.1) ─────────────────────────
    add("gtpc2-control", "gtpc2",
        "nothing (the control): version 2, P and T set, three well-formed IEs",
        "TS 29.274 5.1 / 8.2 / 8.3",
        "parse every IE in order and answer the message: the baseline the "
        "single-field cases below are measured against",
        gtp_c2(32, teid, seq,
               ie(IE_IMSI, imsi_value(imsi))
               + ie(IE_EPS_BEARER_ID, b"\x05")
               + ie(IE_CAUSE, b"\x10")), 2123)

    add("gtpc2-version-1", "gtpc2", "version in octet 1 (1, a GTPv2-C frame)",
        "TS 29.274 5.1",
        "discard: a v1 header on the v2 port belongs to TS 29.060's grammar, "
        "and reading it as v2 shifts the IE area by four octets",
        gtp_c2(32, teid, seq, flags=0x28), 2123)

    add("gtpc2-spare-octet", "gtpc2", "spare octet after the sequence number",
        "TS 29.274 5.1",
        "ignore it: the octet is spare, so a non-zero value must change nothing "
        "about the message that is understood",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10"))[:11] + b"\xff" + gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10"))[12:], 2123)

    add("gtpc2-teid-without-t", "gtpc2",
        "T bit clear while octets 5-8 hold a TEID",
        "TS 29.274 5.1",
        "ignore the TEID field: T clear means the value is not a tunnel "
        "endpoint, and a node that uses it addresses a session it was never told "
        "about",
        _clear_t(gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10"))), 2123)

    add("gtpc2-length-long", "gtpc2", "length field (longer than the datagram)",
        "TS 29.274 5.1",
        "discard as malformed before parsing any IE: the IE area the length "
        "promises is not there",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10"), length=64), 2123)

    # ── GTPv2-C information elements (TS 29.274 8.2, 8.3, 5.5.1) ──────
    add("gtpc2-imsi-overlong", "gtpc2",
        "IMSI IE length (10 octets where 8 is the shape)",
        "TS 29.274 8.3",
        "reject the IE, not the message: the format is fixed at eight octets, "
        "and a longer one is where a length-driven reader walks off the field",
        gtp_c2(32, teid, seq, ie(IE_IMSI, imsi_value(imsi) + b"\x12\x34")
               + ie(IE_CAUSE, b"\x10")),
        2123)

    add("gtpc2-imsi-short", "gtpc2", "IMSI IE length (4 octets)",
        "TS 29.274 8.3",
        "reject the IE: four octets cannot carry an IMSI, and padding it out "
        "invents digits that were never sent",
        gtp_c2(32, teid, seq, ie(IE_IMSI, imsi_value(imsi)[:4])
               + ie(IE_CAUSE, b"\x10")), 2123)

    add("gtpc2-imsi-padding", "gtpc2",
        "IMSI odd-digit padding octet (0x0 instead of 0xF)",
        "TS 29.274 8.3",
        "report the odd-digit case and do not treat the padding nibble as a "
        "digit; a subscriber id with a trailing zero names somebody else",
        gtp_c2(32, teid, seq,
               ie(IE_IMSI, imsi_value(imsi[:-1]) + b"\x00")
               + ie(IE_CAUSE, b"\x10")), 2123)

    add("gtpc2-ebi-sixteen", "gtpc2",
        "EPS Bearer ID IE value (16, outside the four-bit field)",
        "TS 29.274 8.2 (EPS Bearer ID)",
        "reject the IE: the field is four bits, so 16 is not a bearer this "
        "message can name -- and must not wrap to bearer 0",
        gtp_c2(32, teid, seq, ie(IE_EPS_BEARER_ID, b"\x10")
               + ie(IE_CAUSE, b"\x10")), 2123)

    add("gtpc2-ebi-zero", "gtpc2", "EPS Bearer ID IE value (0)",
        "TS 29.274 8.2 (EPS Bearer ID)",
        "reject the IE: bearer ids start at 5 in the default bearer case, and 0 "
        "is the value a reader must not accept as a bearer",
        gtp_c2(32, teid, seq, ie(IE_EPS_BEARER_ID, b"\x00")
               + ie(IE_CAUSE, b"\x10")), 2123)

    add("gtpc2-ie-length-past-end", "gtpc2",
        "length of the last IE (runs past the message)",
        "TS 29.274 5.1 / 8.2",
        "stop at the message boundary and report the overrun; the IE length "
        "never overrides the message length",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10")
               + ie(IE_F_TEID, b"\x00" * 8, length=200)),
        2123)

    add("gtpc2-ie-zero-length", "gtpc2",
        "length of an IE with a fixed shape (Cause, 0)",
        "TS 29.274 8.2 (Cause) / 5.5.1",
        "reject the IE: Cause is one octet plus spare bits, so a zero-length "
        "Cause tells the reader nothing and must not read as cause 0",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"", length=0)
               + ie(IE_IMSI, imsi_value(imsi))), 2123)

    add("gtpc2-unknown-ie-reject", "gtpc2",
        "an unassigned IE type (240) with criticality reject",
        "TS 29.274 5.5.1",
        "reject the whole message: that is what a reject criticality on an "
        "unknown IE instructs, and it is the case a lenient node answers anyway",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10")
               + ie(240, b"\x01\x02", criticality=0)), 2123)

    add("gtpc2-unknown-ie-ignore", "gtpc2",
        "the same unknown IE with criticality ignore",
        "TS 29.274 5.5.1",
        "process the message and skip the IE: the same octets as the case "
        "above, one criticality bit apart, must get the opposite answer",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10")
               + ie(240, b"\x01\x02", criticality=1)), 2123)

    add("gtpc2-criticality-reserved", "gtpc2",
        "criticality bits of a known IE (3, outside reject/ignore/notify)",
        "TS 29.274 8.2",
        "reject the IE: the table gives three values and a fourth is not a "
        "value a receiver may invent a meaning for",
        gtp_c2(32, teid, seq, ie(IE_CAUSE, b"\x10")
               + ie(IE_IMSI, imsi_value(imsi), criticality=3)),
        2123)

    # ── GTPv1-C header fields (TS 29.060 6.1) ─────────────────────────
    add("gtpc1-version-2", "gtpc1", "version in octet 1 (2, a v1 frame)",
        "TS 29.060 6.1",
        "discard: the three-octet sequence number of v2 does not fit where v1 "
        "puts its two, so a v2 message read as v1 is one octet wrong from the "
        "sequence number on",
        gtp_c1(16, teid, b"\x00\x00\x00\x00", flags=(0x40 | 0x10 | GTPU_FLAG_S),
               seq=seq16), 2123)

    add("gtpc1-flag-without-sequence", "gtpc1",
        "S bit with a length that leaves no octets for the sequence number",
        "TS 29.060 6.1",
        "do not read the sequence number the flag promises when the length "
        "denies it; keep the message classifiable without the number",
        gtp_c1(16, teid, b"", flags=(GTPC1_FLAG_V1_PT | GTPU_FLAG_S), length=0),
        2123)

    add("gtpc1-length-not-multiple", "gtpc1",
        "length field (6, not a multiple of four with S set)",
        "TS 29.060 6.1",
        "report the framing error: the optional fields are four octets each, so "
        "a length that is not a multiple of four cannot be walked",
        gtp_c1(16, teid, b"\x00\x00", flags=(GTPC1_FLAG_V1_PT | GTPU_FLAG_S),
               length=6), 2123)

    return cases


# ---------------------------------------------------------------------------
# writers
# ---------------------------------------------------------------------------

PLAN_HEADER = ["case", "family", "varies", "clause", "must", "octets", "hex",
               "verdict"]


def write_plan(cases, path):
    if not path:
        return
    fresh = not os.path.exists(path) or os.path.getsize(path) == 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as handle:
        if fresh:
            handle.write("\t".join(["utc", "seed"] + PLAN_HEADER) + "\n")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for case in cases:
            handle.write("\t".join([stamp, str(case.get("seed", ""))] +
                                   [str(case.get(column, "planned"))
                                    for column in PLAN_HEADER]) + "\n")


def write_pcap(path, cases):
    """A capture of the whole corpus, framed here rather than by text2pcap.

    text2pcap cannot frame a bare PDU: it needs the link layer and, for GTP,
    the IP and UDP headers too, so this writes Ethernet, IPv4 (checksum
    included), UDP and then the case's own octets.  The port decides which
    dissector reads it: 2123 is GTPv2-C/GTPv1-C, 2152 is GTP-U.
    """
    def ipv4(payload, sport, dport):
        total = 20 + 8 + len(payload)
        header = struct.pack("!BBHHHBBH", 0x45, 0, total, 1, 0, 64, 17, 0)
        src = socket.inet_aton("10.0.0.1")
        dst = socket.inet_aton("10.0.0.2")
        header += src + dst
        # The checksum nobody needs but a strict dissector likes to have right.
        words = struct.unpack("!10H", header)
        acc = 0
        for word in words:
            acc += word
        while acc >> 16:
            acc = (acc & 0xFFFF) + (acc >> 16)
        header = header[:10] + struct.pack("!H", ~acc & 0xFFFF) + header[12:]
        return header + struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

    def ethernet(payload, sport, dport):
        return (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
                + b"\x08\x00" + ipv4(payload, sport, dport))

    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, case in enumerate(cases):
            frame = ethernet(bytes.fromhex(case["hex"]), 20000 + index,
                             case["port"])
            handle.write(struct.pack("<IIII", 1600000000 + index, 0,
                                     len(frame), len(frame)))
            handle.write(frame)


def transmit(cases, host, port, rate, timeout):
    """Send the corpus to one peer, paced, and record what came back.

    Only reached with --transmit.  Silence is written as `unobserved`, never as
    a rejection: a datagram that got no answer proves nothing about the peer.
    """
    results = []
    gap = 1.0 / rate if rate > 0 else 0.0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    for case in cases:
        packet = bytes.fromhex(case["hex"])
        row = dict(case)
        try:
            sock.sendto(packet, (host, case.get("port", port)))
        except OSError as exc:
            row["verdict"] = "send-error: %s" % (exc.strerror or exc,)
            results.append(row)
            continue
        try:
            answer, _ = sock.recvfrom(65535)
        except socket.timeout:
            row["verdict"] = "unobserved"
            results.append(row)
            time.sleep(gap)
            continue
        except OSError as exc:
            row["verdict"] = "recv-error: %s" % (exc.strerror or exc,)
            results.append(row)
            continue
        kind = answer[1] if len(answer) > 1 else None
        row["verdict"] = ("answered-type:%02X" % kind) if kind is not None \
            else "answered-short"
        results.append(row)
        time.sleep(gap)
    sock.close()
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="GTP-C/GTP-U fuzz corpus: plan by default, transmit only "
                    "with --transmit, and only to a lab you own.")
    parser.add_argument("--seed", type=int, default=0,
                        help="the corpus is a function of this and nothing else")
    parser.add_argument("--family", default="all",
                        help="gtpu | gtpc2 | gtpc1 | all (default all)")
    parser.add_argument("--max", type=int, default=0,
                        help="stop after N cases (0 = every case)")
    parser.add_argument("--plan-tsv", default="",
                        help="append the plan rows here (loot/<module>/*.tsv)")
    parser.add_argument("--pcap", default="",
                        help="write the corpus as a capture for a dissector")
    parser.add_argument("--transmit", action="store_true",
                        help="SEND the cases: lab use only, this is the flag "
                             "that puts datagrams on a socket")
    parser.add_argument("--host", default="",
                        help="the peer to transmit to (needs --transmit)")
    parser.add_argument("--port", type=int, default=0,
                        help="override the per-case port")
    parser.add_argument("--rate", type=float, default=8.0,
                        help="cases per second when transmitting (default 8)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="seconds to wait for an answer (default 1)")
    args = parser.parse_args(argv)

    if args.seed < 0:
        sys.stderr.write("ERROR\t--seed is a non-negative integer\n")
        return 2
    if args.family not in ("all", "gtpu", "gtpc2", "gtpc1"):
        sys.stderr.write("ERROR\t--family is gtpu, gtpc2, gtpc1 or all; got %r\n"
                         % (args.family,))
        return 2
    if args.rate <= 0:
        sys.stderr.write("ERROR\t--rate must be more than zero packets a second\n")
        return 2
    if args.transmit and not args.host:
        sys.stderr.write("ERROR\t--transmit needs --host: the cases go to a "
                         "peer you name, never to a broadcast\n")
        return 2

    cases = build_cases(args.seed)
    if args.family != "all":
        cases = [case for case in cases if case["family"] == args.family]
    if args.max:
        cases = cases[:args.max]
    if not cases:
        sys.stderr.write("ERROR\tno case matches family %r\n" % (args.family,))
        return 2
    for case in cases:
        case["seed"] = args.seed
        if args.port:
            case["port"] = args.port

    family_counts = {}
    for case in cases:
        family_counts[case["family"]] = family_counts.get(case["family"], 0) + 1

    if args.pcap:
        write_pcap(args.pcap, cases)

    rows = cases
    if args.transmit:
        rows = transmit(cases, args.host, args.port or 0, args.rate, args.timeout)

    sys.stdout.write("case\tfamily\tvaries\tclause\tmust\toctets\thex\tverdict\n")
    for row in rows:
        sys.stdout.write("\t".join(str(row.get(key, "planned")) for key in
                                   ("case", "family", "varies", "clause", "must",
                                    "octets", "hex", "verdict")) + "\n")

    if args.plan_tsv:
        write_plan(rows, args.plan_tsv)

    mode = "transmitted" if args.transmit else "planned"
    sys.stdout.write("mode\t%s\n" % (mode,))
    sys.stdout.write("seed\t%d\n" % (args.seed,))
    sys.stdout.write("cases\t%d\n" % (len(rows),))
    for family in sorted(family_counts):
        sys.stdout.write("family_%s\t%d\n" % (family, family_counts[family]))
    if args.transmit:
        answered = sum(1 for row in rows if row["verdict"].startswith("answered"))
        errored = sum(1 for row in rows if row["verdict"].endswith("error") or
                      "error" in row["verdict"])
        sys.stdout.write("answered\t%d\n" % (answered,))
        sys.stdout.write("unobserved\t%d\n" % (len(rows) - answered - errored,))
        sys.stdout.write("send_error\t%d\n" % (errored,))
        sys.stdout.write("note\tsilence is unobserved, not a rejection: only an "
                         "answer of any kind proves the peer read the case\n")
    else:
        sys.stdout.write("note\tnothing was sent: no case leaves this machine "
                         "without --transmit, and every row is a plan\n")
    sys.stdout.write("clauses\tTS 29.281 5.1/5.2.1/5.2.2/7.1/7.3, "
                     "TS 29.274 5.1/5.5.1/8.2/8.3, TS 29.060 6.1\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
