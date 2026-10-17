#!/usr/bin/env python3
"""TCP and TLS, for the two modules whose PDUs are framed and then never sent.

Why one file for Diameter and the service-based architecture
------------------------------------------------------------
They are the same mechanism: connect, optionally wrap in TLS, write octets that
another module already built, read whatever comes back.  A Diameter peer on 3868
and an SBI NF on 443 differ in what the octets mean, not in how they travel.
Building them apart would be the mistake T1 made when it filed the transport as
a free-floating slot -- two copies of one idea drift, and this tree has paid for
that before with the OTA SPI layout.

What this is not
----------------
It is not an HTTP/2 client.  HTTP/2 needs the connection preface, a SETTINGS
exchange, stream identifiers and HPACK-compressed headers; ``40_sba_pivot``
already builds and parses those frames, so the request body is supplied to this
file whole and the report says ``framing none``.  A caller who sends a raw JSON
body to an SBI NF and expects an answer is sending a valid TLS record and an
invalid HTTP/2 message, and the far end will say so on its own.

It is not a Diameter stack either: no CER/CEA handshake is performed, no answer
is matched to a request by hop-by-hop id.  It sends and it reads.

TLS, and the one thing it must never do quietly
-----------------------------------------------
Verification is on by default.  ``--insecure`` turns it off and the report then
says ``verification none`` in as many words, because a TLS connection that
authenticated nobody is not the same object as one that did, and the difference
has to be visible in a log that outlives the session.  The selftest asserts
both directions: a self-signed certificate fails the default path, and succeeds
only when the caller said ``--insecure``.

Ports
-----
``3868``  Diameter, RFC 6733 §3.1 (SCTP or TCP)
``443``   HTTP/2 over TLS, the SBI's southbound edge (TS 29.500)
``8080``  an SBI NF's plain HTTP, TS 29.500 (never over a real 5G core)
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

PORT_DIAMETER = 3868
PORT_SBI = 443


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


def make_cert(directory: str) -> tuple[str, str]:
    """A throwaway self-signed certificate, for the selftest and for a lab peer."""
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def _tls_context(server: bool, cert: str | None, key: str | None,
                 insecure: bool) -> ssl.SSLContext:
    if server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_default_certs()
    return ctx


def send_stream(host: str, port: int, payload: bytes, use_tls: bool = False,
                insecure: bool = False, sni: str | None = None,
                timeout: float = 5.0, wait: float = 0.0,
                expect_bytes: int | None = None) -> dict:
    """Connect, optionally wrap in TLS, write the octets, optionally read back."""
    report = {
        "protocol": "tls" if use_tls else "tcp",
        "target": "%s:%d" % (host, port),
        "octets": str(len(payload)),
        "hex": payload.hex(),
    }
    if not payload:
        report["status"] = "empty"
        report["error"] = "nothing to send; a TCP connect with no octets is a probe"
        return report

    ctx = None
    if use_tls:
        report["verification"] = "none" if insecure else "default trust store"
        if insecure:
            report["warning"] = ("CERT_NONE: this connection authenticated nobody, "
                                 "so the far end is only as named as its address")
        try:
            ctx = _tls_context(False, None, None, insecure)
        except Exception as exc:  # noqa: BLE001 - the reason matters more than the class
            report["status"] = "failed"
            report["error"] = "tls context: %s" % (exc,)
            return report

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        try:
            raw.connect((host, port))
        except socket.timeout:
            report["status"] = "timeout"
            report["error"] = ("no TCP answer within %.1fs; nothing is listening or the "
                               "path is filtered" % timeout)
            return report
        except ConnectionRefusedError:
            report["status"] = "refused"
            report["error"] = "the far end answered and refused: nothing is listening"
            return report
        except OSError as exc:
            report["status"] = "failed"
            report["error"] = "connect: %s" % (errno.errorcode.get(exc.errno, exc.errno),)
            return report

        report["connected"] = "yes"

        sock: socket.socket | ssl.SSLSocket = raw
        if ctx is not None:
            try:
                sock = ctx.wrap_socket(raw, server_hostname=sni or host)
            except ssl.SSLError as exc:
                report["status"] = "tls-failed"
                report["error"] = ("the peer did not complete a TLS handshake: %s"
                                   % (exc.reason or exc,))
                return report
            report["tls_version"] = sock.version() or "unknown"
            cipher = sock.cipher()
            report["tls_cipher"] = cipher[0] if cipher else "unknown"

        sock.sendall(payload)
        report["sent"] = "yes"
        report["status"] = "sent"

        if wait > 0 or expect_bytes:
            budget = max(wait, 0.1)
            sock.settimeout(budget)
            chunks: list[bytes] = []
            want = expect_bytes or 0
            try:
                while True:
                    chunk = sock.recv(65535)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if want and sum(len(c) for c in chunks) >= want:
                        break
            except socket.timeout:
                pass
            data = b"".join(chunks)
            report["reply_octets"] = str(len(data))
            if data:
                report["reply_hex"] = data.hex()
                report["status"] = "sent-and-answered"
            else:
                report["delivery"] = ("no octets came back within %.1fs; for Diameter that "
                                      "means no CEA or no answer, not proof of arrival" % budget)
        return report
    finally:
        try:
            raw.close()
        except OSError:
            pass


def serve_once(port: int, host: str = "127.0.0.1", use_tls: bool = False,
               cert: str | None = None, key: str | None = None,
               timeout: float = 10.0) -> list[dict]:
    """Accept one connection, read one chunk, and answer with `ok` if asked."""
    rows: list[dict] = []
    ctx = _tls_context(True, cert, key, False) if use_tls else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout)
        actual = srv.getsockname()[1]
        conn, peer = srv.accept()
        with conn:
            link = ctx.wrap_socket(conn, server_side=True) if ctx else conn
            link.settimeout(timeout)
            data = link.recv(65535)
            rows.append({
                "listen": "%s:%d" % (host, actual),
                "peer": "%s:%d" % peer,
                "protocol": "tls" if use_tls else "tcp",
                "octets": str(len(data)),
                "hex": data.hex(),
                "status": "received",
            })
    finally:
        try:
            srv.close()
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


def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)


def selftest() -> int:
    """Plaintext, TLS, and the direction that must fail: an unverified peer."""
    passed: list[str] = []
    failed: list[str] = []
    payload = bytes.fromhex("0101004c80000001000000002c0101")
    tmp = tempfile.mkdtemp(prefix="stream-assoc-")
    cert, key = make_cert(tmp)

    # ── plaintext ────────────────────────────────────────────────────────
    got: dict = {}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve_plain():
        conn, _peer = srv.accept()
        with conn:
            conn.settimeout(5.0)
            got["data"] = conn.recv(65535)
            conn.sendall(b"answered:" + got.get("data", b""))
        srv.close()

    thread = threading.Thread(target=serve_plain, daemon=True)
    thread.start()
    report = send_stream("127.0.0.1", port, payload, wait=2.0)
    thread.join(5.0)
    _check("tcp-sends", report.get("status") == "sent-and-answered", str(report.get("status")),
           passed, failed)
    _check("tcp-arrives-whole", got.get("data") == payload, "got %r" % (got.get("data", b""),),
           passed, failed)
    _check("tcp-reply-read", str(report.get("reply_hex", "")).startswith("616e737765726564"),
           str(report.get("reply_hex"))[:16], passed, failed)

    # ── TLS, verification off, explicitly ───────────────────────────────
    srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv2.bind(("127.0.0.1", 0))
    srv2.listen(1)
    port2 = srv2.getsockname()[1]
    got2: dict = {}
    ctx = _tls_context(True, cert, key, False)

    def serve_tls():
        conn, _peer = srv2.accept()
        try:
            link = ctx.wrap_socket(conn, server_side=True)
            with link:
                link.settimeout(5.0)
                got2["data"] = link.recv(65535)
                link.sendall(b"tls-ok")
        except ssl.SSLError as exc:
            got2["error"] = str(exc)
        finally:
            srv2.close()

    thread2 = threading.Thread(target=serve_tls, daemon=True)
    thread2.start()
    tls_report = send_stream("127.0.0.1", port2, payload, use_tls=True,
                            insecure=True, wait=2.0)
    thread2.join(5.0)
    _check("tls-handshakes", tls_report.get("status") == "sent-and-answered",
           str(tls_report.get("status")), passed, failed)
    _check("tls-carries-the-octets", got2.get("data") == payload,
           "got %r" % (got2.get("data", b""),), passed, failed)
    _check("tls-reports-version", str(tls_report.get("tls_version", "")).startswith("TLS"),
           str(tls_report.get("tls_version")), passed, failed)
    _check("insecure-is-labelled",
           tls_report.get("verification") == "none"
           and "authenticated nobody" in str(tls_report.get("warning")),
           str(tls_report.get("verification")), passed, failed)

    # ── the direction that must fail ────────────────────────────────────
    # A self-signed certificate against the default trust store is a verification
    # failure, and a verification failure must not look like a send.
    srv3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv3.bind(("127.0.0.1", 0))
    srv3.listen(1)
    port3 = srv3.getsockname()[1]

    def serve_tls_strict():
        conn, _peer = srv3.accept()
        try:
            link = ctx.wrap_socket(conn, server_side=True)
            link.close()
        except (ssl.SSLError, OSError):
            pass
        finally:
            srv3.close()

    thread3 = threading.Thread(target=serve_tls_strict, daemon=True)
    thread3.start()
    strict = send_stream("127.0.0.1", port3, payload, use_tls=True,
                         insecure=False, wait=1.0)
    thread3.join(5.0)
    _check("verification-is-on-by-default", strict.get("status") == "tls-failed",
           str(strict.get("status")), passed, failed)
    _check("verification-failure-does-not-send", strict.get("sent") is None,
           "sent=%r" % (strict.get("sent"),), passed, failed)

    # TLS against a listener that never speaks TLS: distinguishable, not hung.
    srv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv4.bind(("127.0.0.1", 0))
    srv4.listen(1)
    port4 = srv4.getsockname()[1]

    def serve_plain_forever():
        conn, _peer = srv4.accept()
        try:
            conn.recv(1024)
            conn.sendall(b"not tls at all")
        finally:
            conn.close()
            srv4.close()

    thread4 = threading.Thread(target=serve_plain_forever, daemon=True)
    thread4.start()
    mismatch = send_stream("127.0.0.1", port4, payload, use_tls=True,
                           insecure=True, timeout=3.0)
    thread4.join(5.0)
    _check("tls-to-plaintext-is-named",
           mismatch.get("status") in ("tls-failed", "timeout"),
           str(mismatch.get("status")), passed, failed)

    # A closed port is refused, and refused is not sent.
    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    refused = send_stream("127.0.0.1", closed_port, payload)
    _check("closed-port-refused", refused.get("status") == "refused",
           str(refused.get("status")), passed, failed)
    _check("refused-does-not-send", refused.get("sent") is None,
           "sent=%r" % (refused.get("sent"),), passed, failed)

    empty = send_stream("127.0.0.1", 9, b"")
    _check("empty-refused", empty.get("status") == "empty", str(empty.get("status")),
           passed, failed)

    _check("norm-hex-separators", norm_hex("01:01-00.4c 80\t00") == "0101004c8000",
           norm_hex("01:01-00.4c 80\t00"), passed, failed)
    try:
        norm_hex("010")
        _check("norm-hex-odd", False, "no error", passed, failed)
    except ValueError:
        _check("norm-hex-odd", True, "", passed, failed)

    _check("ports-are-standard", (PORT_DIAMETER, PORT_SBI) == (3868, 443),
           "%d %d" % (PORT_DIAMETER, PORT_SBI), passed, failed)

    print("ASSERTIONS\t%d" % (len(passed) + len(failed)))
    print("RESULT\t%s" % ("PASS" if not failed else "FAIL"))
    return 0 if not failed else 1


def _emit(report: dict) -> None:
    for key, value in report.items():
        print("%s\t%s" % (key, _printable(str(value))))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="TCP and TLS for the core modules")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("send", help="connect, optionally TLS, send one message")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("payload", help="hex octets, a file of them, or - for stdin")
    p.add_argument("--tls", action="store_true")
    p.add_argument("--insecure", action="store_true",
                   help="do not verify the peer; the report will say so")
    p.add_argument("--sni", default=None)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--wait", type=float, default=0.0,
                   help="seconds to wait for octets back")
    p.add_argument("--expect-bytes", type=int, default=None)

    p = sub.add_parser("serve", help="accept one connection and read it")
    p.add_argument("port", type=int)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--tls", action="store_true")
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--timeout", type=float, default=10.0)

    p = sub.add_parser("cert", help="write a throwaway self-signed cert")
    p.add_argument("directory", nargs="?", default=".")

    p = sub.add_parser("ports", help="the TCP ports this tree uses")
    del p

    sub.add_parser("selftest", help="plaintext, TLS, and the failure that must not send")

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
            _emit(send_stream(args.host, args.port, bytes.fromhex(norm_hex(text)),
                              use_tls=args.tls, insecure=args.insecure, sni=args.sni,
                              timeout=args.timeout, wait=args.wait,
                              expect_bytes=args.expect_bytes))
        elif args.verb == "serve":
            for row in serve_once(args.port, args.host, args.tls, args.cert, args.key,
                                  args.timeout):
                _emit(row)
        elif args.verb == "cert":
            cert, key = make_cert(args.directory)
            print("cert\t%s" % cert)
            print("key\t%s" % key)
            print("verification\tthis certificate is self-signed; a peer verifying "
                  "against a trust store will refuse it")
        elif args.verb == "ports":
            print("port\tprotocol\twhere")
            print("3868\tDiameter\tRFC 6733 §3.1; SCTP or TCP, and the SCTP leg is sctp_assoc.py")
            print("443\tHTTP/2 over TLS\tTS 29.500; the SBI's southbound edge")
            print("8080\tHTTP/2 plain\tTS 29.500; lab only, never a real core")
        elif args.verb == "selftest":
            return selftest()
        else:
            parser.print_help()
            return 2
    except ValueError as exc:
        print("ERROR\t%s" % exc, file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print("ERROR\tcertificate generation failed: %s" % (exc,), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
