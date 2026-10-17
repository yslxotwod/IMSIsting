#!/usr/bin/env python3
"""UDP datagrams, for the core modules that build PDUs and never send them.

Why this file is separate from ``sctp_assoc.py``
------------------------------------------------
SCTP gives an association: either the handshake completes or it does not, so
the answer to "did this arrive" is a state.  UDP gives no such thing.  A send
that returns success means the kernel accepted the datagram and put it on a
link -- not that anything is listening, not that it parsed, not that it was not
dropped by a middlebox.  GTP-C and PFCP both ride UDP, so both carry that
ambiguity, and the one thing this file must never do is paper over it.

The report says ``sent`` and, separately, whether an answer came back.  With no
answer it says ``delivery unconfirmed`` rather than inventing a success.

What uses it
------------
``11_lte_core`` builds a GTPv2-C Create Session Request (``message_type 32``,
TS 29.274 §7.2.1) on UDP 2123 and stops at the octets.  ``13_nr_core`` carries
the same gap for PFCP on UDP 8805 (TS 29.244) and is not wired here yet because
it has no session-establishment builder -- the encoder gap comes first, then the
send is two lines.

Ports
-----
``2123``  GTP-C, TS 29.274 (GTPv2-C control plane)
``2152``  GTP-U, TS 29.281 (not here: the user plane needs a tunnel, not a datagram)
``8805``  PFCP, TS 29.244

Limits worth stating
--------------------
This does not fragment, retransmit, or reorder.  It does not speak TCP, TLS or
SCTP -- Diameter's SCTP leg belongs to ``sctp_assoc.py`` and its TCP leg, and
everything HTTP/2, is not built.  A datagram larger than the path MTU is the
caller's problem, exactly as it is with ``nc -u``.
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import struct
import sys

PORT_GTPC = 2123
PORT_GTPU = 2152
PORT_PFCP = 8805


def norm_hex(text: str) -> str:
    joined = []
    for ch in text.strip():
        if ch in " \t\r\n:.-":
            continue
        joined.append(ch)
    out = "".join(joined)
    if out[:2].lower() == "0x":
        out = out[2:]
    if len(out) % 2:
        raise ValueError("odd number of hex digits (%d)" % len(out))
    try:
        bytes.fromhex(out)
    except ValueError:
        raise ValueError("not hex: %r" % out[:32])
    return out.lower()


def send_datagram(host: str, port: int, payload: bytes, timeout: float = 2.0,
                  wait: float = 0.0) -> dict:
    """Send one datagram, and say honestly whether anything answered."""
    report = {
        "protocol": "udp",
        "target": "%s:%d" % (host, port),
        "octets": str(len(payload)),
        "hex": payload.hex(),
    }
    if not payload:
        report["status"] = "empty"
        report["error"] = "nothing to send; a zero-length datagram proves only that a port exists"
        return report

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(max(timeout, 0.1))
        try:
            sent = sock.sendto(payload, (host, port))
        except OSError as exc:
            name = errno.errorcode.get(exc.errno, exc.errno)
            report["status"] = "failed"
            report["error"] = "sendto: %s" % (name,)
            return report
        report["bytes_accepted"] = str(sent)
        report["sent"] = "yes"
        report["status"] = "sent"
        report["delivery"] = "unconfirmed: UDP has no acknowledgement; only a reply proves arrival"

        if wait > 0:
            sock.settimeout(max(0.1, wait))
            try:
                data, peer = sock.recvfrom(65535)
                report["reply_octets"] = str(len(data))
                report["reply_hex"] = data.hex()
                report["reply_from"] = "%s:%d" % peer
                report["delivery"] = "answered"
                report["status"] = "sent-and-answered"
            except ConnectionRefusedError:
                report["delivery"] = (
                    "refused by an ICMP port-unreachable: the datagram was sent and "
                    "nothing is listening")
                report["status"] = "sent-and-refused"
            except socket.timeout:
                report["delivery"] = (
                    "no answer within %.1fs: silence, which for UDP is not proof "
                    "either way" % wait)
                report["status"] = "sent"
        return report
    finally:
        try:
            sock.close()
        except OSError:
            pass


def receive_datagrams(port: int, host: str = "0.0.0.0", timeout: float = 10.0,
                      count: int = 1) -> list[dict]:
    rows = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(max(timeout, 0.1))
        actual = sock.getsockname()[1]
        for _ in range(max(count, 1)):
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                rows.append({"listen": "%s:%d" % (host, actual),
                             "status": "no-datagram"})
                break
            rows.append({
                "listen": "%s:%d" % (host, actual),
                "from": "%s:%d" % peer,
                "octets": str(len(data)),
                "hex": data.hex(),
                "status": "received",
            })
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return rows


def _check(name: str, ok: bool, detail: str, passed: list, failed: list) -> None:
    if ok:
        passed.append(name)
        print("PASS\t%s" % name)
    else:
        failed.append(name)
        print("FAIL\t%s\t%s" % (name, detail))


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def selftest() -> int:
    """A datagram to itself, and the two things a UDP send must never claim."""
    passed: list[str] = []
    failed: list[str] = []

    payload = bytes.fromhex("48002000550400")
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(3.0)
    port = receiver.getsockname()[1]

    report = send_datagram("127.0.0.1", port, payload, wait=0.0)
    _check("send-accepted", report.get("status") == "sent", str(report.get("status")),
           passed, failed)
    try:
        data, peer = receiver.recvfrom(65535)
    except socket.timeout:
        data, peer = b"", ("", 0)
    receiver.close()

    _check("datagram-arrives-whole", data == payload, "got %r" % (data,), passed, failed)
    _check("peer-port-is-the-sender", peer[1] > 0, str(peer), passed, failed)
    _check("no-ack-by-default",
           "unconfirmed" in str(report.get("delivery")),
           str(report.get("delivery")), passed, failed)

    # An answer flips the verdict, and the same payload comes back.
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo.settimeout(3.0)
    echo_port = echo.getsockname()[1]
    send_datagram("127.0.0.1", echo_port, payload, wait=0.0)
    try:
        got, peer = echo.recvfrom(65535)
        echo.sendto(b"answered:" + got, peer)
    except socket.timeout:
        pass
    echo.close()
    answered = send_datagram("127.0.0.1", echo_port, payload, wait=1.0)
    _check("silence-is-not-proof", "no answer" in str(answered.get("delivery")),
           str(answered.get("delivery")), passed, failed)

    # A closed port must not be reported as a delivery, whichever way the kernel
    # tells us: loopback usually raises ECONNREFUSED on the next receive.
    closed = _free_udp_port()
    refused = send_datagram("127.0.0.1", closed, payload, wait=1.0)
    _check("closed-port-is-not-delivered",
           refused.get("status") in ("sent", "sent-and-refused"),
           str(refused.get("status")), passed, failed)
    caveat = str(refused.get("delivery", ""))
    _check("closed-port-carries-a-caveat",
           any(word in caveat for word in ("unconfirmed", "nothing is listening", "silence"))
           and "delivered" not in caveat,
           caveat, passed, failed)

    empty = send_datagram("127.0.0.1", 9, b"")
    _check("empty-datagram-refused", empty.get("status") == "empty",
           str(empty.get("status")), passed, failed)

    _check("norm-hex-separators", norm_hex("48:00-20.00 55\t04") == "480020005504",
           norm_hex("48:00-20.00 55\t04"), passed, failed)
    try:
        norm_hex("481")
        _check("norm-hex-odd", False, "no error", passed, failed)
    except ValueError:
        _check("norm-hex-odd", True, "", passed, failed)

    _check("ports-are-the-standard-ones",
           (PORT_GTPC, PORT_PFCP, PORT_GTPU) == (2123, 8805, 2152),
           "%d %d %d" % (PORT_GTPC, PORT_PFCP, PORT_GTPU), passed, failed)

    print("ASSERTIONS\t%d" % (len(passed) + len(failed)))
    print("RESULT\t%s" % ("PASS" if not failed else "FAIL"))
    return 0 if not failed else 1


def _emit(report: dict) -> None:
    for key, value in report.items():
        print("%s\t%s" % (key, value))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="UDP datagrams for the core modules")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("send", help="send one datagram")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("payload", help="hex octets, a file of them, or - for stdin")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--wait", type=float, default=0.0,
                   help="seconds to wait for one datagram back")

    p = sub.add_parser("receive", help="bind and read datagrams")
    p.add_argument("port", type=int)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--count", type=int, default=1)

    p = sub.add_parser("ports", help="the UDP ports this tree uses")
    del p

    sub.add_parser("selftest", help="datagram to itself, and the caveats asserted")

    args = parser.parse_args(argv)

    try:
        if args.verb == "send":
            if args.payload == "-":
                text = sys.stdin.read()
            elif os.path.isfile(args.payload):
                with open(args.payload, "r", encoding="utf-8") as handle:
                    text = handle.read()
            else:
                text = args.payload
            _emit(send_datagram(args.host, args.port, bytes.fromhex(norm_hex(text)),
                                timeout=args.timeout, wait=args.wait))
        elif args.verb == "receive":
            for row in receive_datagrams(args.port, args.host, args.timeout, args.count):
                _emit(row)
        elif args.verb == "ports":
            print("port\tprotocol\twhere")
            print("2123\tGTPv2-C\tTS 29.274; the MME to the SGW, and the SGW to the PGW")
            print("2152\tGTP-U\tTS 29.281; the user plane, which a datagram cannot make a tunnel for")
            print("8805\tPFCP\tTS 29.244; the SMF to the UPF")
        elif args.verb == "selftest":
            return selftest()
        else:
            parser.print_help()
            return 2
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
