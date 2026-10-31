#!/usr/bin/env python3
"""One probe per target across an interconnect prefix, and three answers.

Why this is a separate file from ``udp_assoc.py``
-------------------------------------------------
``udp_assoc.py`` sends one datagram to one host and reports, honestly, that a
successful send proves nothing.  That is the right shape for a message the tree
built and a human chose to publish.  It is the wrong shape for a sweep: a sweep
asks the same small question of many addresses and lives or dies on how it
classifies silence.

The sweep question is *is anything there, and does it speak this protocol*.
Three outcomes, and the third one is the point:

  answered        a reply arrived and it parses as the protocol it claims
  spoke-otherwise a reply arrived and it does not parse as that protocol
  silence         nothing came back -- filtered, absent, asymmetric, or off-path

``silence`` is never folded into "closed" and never into "denied".  A GRX/IPX
prefix is full of middleboxes that drop without answering, and a scanner that
calls that a closed port turns a firewall into a finding.  The caller
(``11_lte_core --grx-scan``) maps these onto echo-reply / error-unknown /
unobserved; this file only reports what the socket did and how many
milliseconds it took to not do it.

Probes
------
``gtpc``      GTPv2-C Echo Request on UDP 2123 (TS 29.274 §7.1).  A node that
              answers with Echo Response is a GTP-C peer; an answer that is GTP
              but not an Echo is reported separately, because an error to an
              unknown TEID means the port is a peer and the message was wrong,
              which is a different fact from "nothing there".
``gtpu``      GTPv1-U Echo Request on UDP 2152 (TS 29.281 §7.2).
``diameter``  TCP 3868, then a Capabilities-Exchange-Request.  A TCP accept is
              not a Diameter answer and is not reported as one; only a message
              that parses as a Diameter header counts.  A peer that accepts and
              stays mute is ``tcp-open-no-answer``.
``sctp``      An SCTP association on 38412 (N2) or the port given.  The kernel
              completes INIT/INIT-ACK/COOKIE or it does not, so an established
              association is a state rather than an inference.

What this does not do
---------------------
It does not retransmit, spoof a source address, or walk a range on its own: the
target list arrives on stdin or as a file.  It does not attempt authentication,
encryption, or any protocol beyond the four above.  It sends probes.  Whether a
host on the other side of an interconnect should be swept at all is the
operator's question, and ``11_lte_core --grx-scan`` refuses to invent the
answer by shipping a default prefix.

Output
------
One TSV row per target, no header (the caller writes it):

    addr  port  proto  outcome  rtt_ms  detail

``rtt_ms`` is ``-`` when no reply came.  ``detail`` is a short token, never a
sentence.
"""

from __future__ import annotations

import argparse
import errno
import re
import socket
import struct
import sys
import time

# GTPv2-C Echo Request: flags 0x40 (version 2, no TEID), type 1, length 9
# (4 octets of sequence + spare, then a 5-octet Recovery IE), sequence 1,
# spare 0, Recovery IE (type 3, length 1, restart counter 0).  TS 29.274 §7.1
# carries the Echo, §8.5 the Recovery IE.
GTPC_ECHO = bytes.fromhex("400100090000010003000100")

# GTPv1-U Echo Request: flags 0x32 (version 1, PT=1, no TEID), type 1,
# length 4, sequence 1, spare 0.  TS 29.281 §7.2.
GTPU_ECHO = bytes.fromhex("3201000400010000")

GTPC_RECOVERY_IE = 3
GTPC_ECHO_REQ = 1
GTPC_ECHO_RSP = 2

DIAMETER_CER_CMD = 257


def _avp(code: int, flags: int, value: bytes) -> bytes:
    """One Diameter AVP: code(4) flags(1) length(4) value, then 4-octet pad."""
    length = 8 + len(value)
    pad = (-length) % 4
    return struct.pack(">IBI", code, flags, length) + value + b"\x00" * pad


def diameter_cer(host: str, realm: str = "probe.invalid") -> bytes:
    """A Capabilities-Exchange-Request (RFC 6733 §5.3, command code 257).

    The mandatory AVPs are Origin-Host, Origin-Realm, Host-IP-Address,
    Vendor-Id, Product-Name and Origin-State-Id.  All of them are present
    because a CER missing one draws a CEA carrying DIAMETER_MISSING_AVP from
    some stacks and is dropped by others, and a probe dropped by the far end
    for being malformed tells you nothing about whether the peer exists.
    """
    m = 0x40
    body = b""
    body += _avp(264, m, host.encode())                      # Origin-Host
    body += _avp(296, m, realm.encode())                     # Origin-Realm
    body += _avp(257, m, b"\x00\x01" + socket.inet_aton("0.0.0.0"))  # Host-IP-Address
    body += _avp(266, m, struct.pack(">I", 0))               # Vendor-Id
    body += _avp(269, m, b"grx-probe")                       # Product-Name
    body += _avp(278, m, struct.pack(">I", 1))               # Origin-State-Id
    length = 20 + len(body)
    hdr = struct.pack(">BI", 1, length) + struct.pack(">I", 0x80) + \
        struct.pack(">I", DIAMETER_CER_CMD) + struct.pack(">I", 0) + \
        struct.pack(">II", 1, 1)
    return hdr + body


def _gtp_message_type(data: bytes) -> tuple[int, int]:
    """(flags, message type) from a GTPv1/v2 header, or (-1, -1)."""
    if len(data) < 8:
        return (-1, -1)
    flags = data[0]
    version = (flags >> 5) & 0x07
    if version not in (1, 2):
        return (-1, -1)
    return (version, data[1])


def probe_udp(addr: str, port: int, payload: bytes, timeout: float) -> tuple[str, float | None, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((addr, port))
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-send"))
    start = time.monotonic()
    try:
        sock.send(payload)
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-send"))
    try:
        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        sock.close()
        return ("timeout", None, "no-reply")
    except ConnectionRefusedError:
        # ICMP port unreachable: the host answered for its stack.  This is not
        # the same fact as silence and must not be reported as it.
        sock.close()
        return ("unreachable", None, "icmp-port-unreachable")
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-recv"))
    rtt = (time.monotonic() - start) * 1000.0
    sock.close()
    version, mtype = _gtp_message_type(data)
    if version < 0:
        return ("non-gtp", rtt, "%d-octets" % len(data))
    return ("gtp", rtt, "v%d-type-%d" % (version, mtype))


def _gtp_fields(detail: str) -> tuple[int, int]:
    """(version, message type) out of a ``vN-type-M`` detail token."""
    m = re.match(r"v(\d)-type-(\d+)$", detail)
    if not m:
        return (-1, -1)
    return (int(m.group(1)), int(m.group(2)))


def probe_gtpc(addr: str, port: int, timeout: float) -> tuple[str, float | None, str]:
    outcome, rtt, detail = probe_udp(addr, port, GTPC_ECHO, timeout)
    if outcome != "gtp":
        return (outcome, rtt, detail)
    version, mtype = _gtp_fields(detail)
    if version == 2 and mtype == GTPC_ECHO_RSP:
        return ("gtp-echo", rtt, "echo-response")
    return ("gtp-other", rtt, "v%d-type-%d" % (version, mtype))


def probe_gtpu(addr: str, port: int, timeout: float) -> tuple[str, float | None, str]:
    outcome, rtt, detail = probe_udp(addr, port, GTPU_ECHO, timeout)
    if outcome != "gtp":
        return (outcome, rtt, detail)
    version, mtype = _gtp_fields(detail)
    if version == 1 and mtype == 2:
        return ("gtp-echo", rtt, "echo-response")
    return ("gtp-other", rtt, "v%d-type-%d" % (version, mtype))


def probe_diameter(addr: str, port: int, timeout: float) -> tuple[str, float | None, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((addr, port))
    except socket.timeout:
        sock.close()
        return ("timeout", None, "connect-timeout")
    except ConnectionRefusedError:
        sock.close()
        return ("unreachable", None, "conn-refused")
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-conn"))
    try:
        sock.sendall(diameter_cer(addr))
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-send"))
    try:
        data = sock.recv(2048)
    except socket.timeout:
        sock.close()
        return ("tcp-open-no-answer", None, "tcp-accepted")
    except OSError:
        sock.close()
        return ("tcp-open-no-answer", None, "tcp-accepted")
    rtt = (time.monotonic() - start) * 1000.0
    sock.close()
    if len(data) < 20 or data[0] != 1:
        return ("non-diameter", rtt, "%d-octets" % len(data))
    command = struct.unpack(">I", data[5:9])[0] & 0xFFFFFF
    return ("diameter-reply", rtt, "command-%d" % command)


def probe_sctp(addr: str, port: int, timeout: float) -> tuple[str, float | None, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    except OSError as exc:
        return ("unsupported", None, errno.errorcode.get(exc.errno, "e-sctp"))
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((addr, port))
    except socket.timeout:
        sock.close()
        return ("timeout", None, "init-timeout")
    except ConnectionRefusedError:
        sock.close()
        return ("unreachable", None, "assoc-aborted")
    except OSError as exc:
        sock.close()
        return ("send-error", None, errno.errorcode.get(exc.errno, "e-conn"))
    rtt = (time.monotonic() - start) * 1000.0
    sock.close()
    return ("sctp-assoc", rtt, "association-established")


PROBES = {
    "gtpc": (2123, probe_gtpc),
    "gtpu": (2152, probe_gtpu),
    "diameter": (3868, probe_diameter),
    "sctp": (38412, probe_sctp),
}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(add_help=True, description="probe one prefix, one protocol")
    p.add_argument("proto", choices=sorted(PROBES))
    p.add_argument("targets", help="file of addresses, one per line, or - for stdin")
    p.add_argument("--port", type=int, default=0, help="override the protocol's default port")
    p.add_argument("--timeout", type=float, default=1.0, help="per-target seconds")
    p.add_argument("--limit", type=int, default=4096, help="stop after this many targets")
    args = p.parse_args(argv)

    default_port, probe = PROBES[args.proto]
    port = args.port or default_port

    if args.targets == "-":
        stream = sys.stdin
        close_stream = False
    else:
        try:
            stream = open(args.targets, "r", encoding="utf-8")
        except OSError as exc:
            print("ERROR\tcannot read %s: %s" % (args.targets, exc.strerror), file=sys.stderr)
            return 1
        close_stream = True

    probed = 0
    try:
        for line in stream:
            addr = line.strip()
            if not addr or addr.startswith("#"):
                continue
            if probed >= args.limit:
                break
            outcome, rtt, detail = probe(addr, port, args.timeout)
            probed += 1
            rtt_s = "-" if rtt is None else "%.1f" % rtt
            print("%s\t%d\t%s\t%s\t%s\t%s" % (addr, port, args.proto, outcome, rtt_s, detail))
            sys.stdout.flush()
    finally:
        if close_stream:
            stream.close()
    return 0 if probed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
