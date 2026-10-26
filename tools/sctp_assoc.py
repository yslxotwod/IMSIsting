#!/usr/bin/env python3
"""SCTP associations, so a built PDU can leave the process.

Why this file exists
--------------------
Every backhaul module in this tree stopped at the same place.  ``37_femtocell``
builds a byte-exact S1 Setup Request and an HNBAP Register Request and then
prints ``sctp_ppid 18``.  ``11_lte_core`` builds GTP-C and Diameter PDUs with
no client.  ``26_ss7_map`` decodes M3UA out of a hex string and opens no
association.  The encoders are verified against a referee; the last hop was a
handoff in each of them, which made the encoders unreachable by any script.

This module is that hop, and nothing else.  It does not encode ASN.1, it does
not know what an MME is, and it never invents payload: it takes octets another
codec already proved and puts them in a DATA chunk with the payload protocol
identifier the receiving stack demultiplexes on.

The Linux kernel speaks SCTP itself, so this is a socket call rather than an
SCTP implementation -- ``socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)`` is the
one-to-one style, where the association looks like a TCP connection and the
PPID rides on the socket rather than on each send.

PPIDs used by this tree
-----------------------
``18``   SCTP payload protocol identifier for S1AP      (TS 36.413)
``20``   HNBAP                                          (tshark maps ppi 20 hnbap)
``19``   RUA, the 3G RANAP user adaptation              (tshark maps ppi 19 rua)
``132``  M3UA, which the SS7 modules would carry          (RFC 4666)
``141``  GTP-C over SCTP is not a thing; GTP-C is UDP/TCP (TS 29.274)

The PPID rides as an ``SCTP_SNDINFO`` control message on each ``sendmsg``, and
is read back on the receiving side from the ``SCTP_RCVINFO`` ancillary data that
``SCTP_RECVRCVINFO`` turns on.  Two things were tried and one of them does not
work on this kernel, which is why the selftest asserts the PPID rather than
assuming it: ``SCTP_DEFAULT_SEND_PARAM`` (socket option 10) is accepted and
silently ignored, so every message carried PPID 0 and a receiving stack had
nothing to demultiplex on.  A wrong PPID is a silent drop at the far end: the association
establishes, the DATA chunk arrives, and the receiving stack discards a payload
it cannot name.  That failure mode is the whole reason this file reports the
PPID it actually carried.

What this does not do
---------------------
It does not authenticate, encrypt, or discover anything.  An SCTP association
to an MME or an HNB-GW is exactly as reachable as the network allows and no
more; the modules gate the call behind an armed flag so a build is never one
typo away from a live association.  Nothing here is a capability the operator
did not already have with ``nc``, ``socat`` or ``sctp_test``.
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import struct
import sys
import threading
import time

IPPROTO_SCTP = 132

# From /usr/include/linux/sctp.h.  Values, not names: the values are stable ABI
# and the names are not exposed by the Python standard library.
SCTP_INITMSG = 2
SCTP_STATUS = 14
SCTP_RECVRCVINFO = 32

# cmsg_type values, enum sctp_cmsg_type, from the same header.
SCTP_SNDINFO = 2
SCTP_RCVINFO = 3

# struct sctp_sndinfo: u16 sid, u16 flags, u32 ppid, u32 context, u32 assoc_id.
#
# The PPID inside this struct is in NETWORK byte order, not host order -- the
# kernel keeps it that way and gives it back the same way in sctp_rcvinfo, which
# is why every reader calls ntohl() on it. Packing the whole struct little-endian
# put our PPID 3 on the wire as 0x03000000, and a real STP said so plainly:
#   Rx SCTP chunk for unknown PPID 50331648
# so the association came up and every message was dropped before M3UA saw it.
# Hence the split format: native u16 head, big-endian u32 ppid, native tail.
_SNDINFO = "<HH"
_SNDINFO_TAIL = "<II"
_SNDINFO_LEN = struct.calcsize(_SNDINFO) + 4 + struct.calcsize(_SNDINFO_TAIL)


def _pack_sndinfo(sid: int, flags: int, ppid: int, context: int, assoc_id: int) -> bytes:
    return (struct.pack(_SNDINFO, sid, flags) + struct.pack(">I", ppid) +
            struct.pack(_SNDINFO_TAIL, context, assoc_id))

# struct sctp_rcvinfo: u16 sid, u16 ssn, u16 flags, 2 pad, u32 ppid, u32 tsn,
# u32 cumtsn, u32 context, u32 assoc_id -- so the PPID sits at octet 8.
_RCVINFO = "<HHHxxIIIII"
_RCVINFO_LEN = struct.calcsize(_RCVINFO)
_RCVINFO_PPID_AT = 8

# The SCTP association states, as SCTP_STATUS reports them.
_STATES = {
    0: "CLOSED",
    1: "COOKIE-WAIT",
    2: "COOKIE-ECHOED",
    3: "ESTABLISHED",
    4: "SHUTDOWN-PENDING",
    5: "SHUTDOWN-SENT",
    6: "SHUTDOWN-RECEIVED",
    7: "SHUTDOWN-ACK-SENT",
}

PPID_S1AP = 18
PPID_HNBAP = 20
PPID_RUA = 19
PPID_M3UA = 132
# E2AP rides its own PPID: 70 is the value O-RAN assigned to the E2 interface,
# distinct from S1AP (18) and M3UA (132), so a capture splits the two cleanly.
PPID_E2AP = 70

PORT_S1AP = 36412
PORT_HNBAP = 29169
PORT_E2AP = 36421


def norm_hex(text: str) -> str:
    """Octets from hex, tolerating the separators another tool printed."""
    keep = []
    for ch in text.strip():
        if ch in " \t\r\n:.-":
            continue
        keep.append(ch)
    joined = "".join(keep)
    if joined[:2].lower() == "0x":
        joined = joined[2:]
    if len(joined) % 2:
        raise ValueError("odd number of hex digits (%d)" % len(joined))
    try:
        bytes.fromhex(joined)
    except ValueError:
        raise ValueError("not hex: %r" % joined[:32])
    return joined.lower()


def send_message(sock: socket.socket, payload: bytes, ppid: int) -> int:
    """Send one message with its PPID as an SCTP_SNDINFO control message."""
    cmsg = (socket.IPPROTO_SCTP, SCTP_SNDINFO, _pack_sndinfo(0, 0, ppid, 0, 0))
    return sock.sendmsg([payload], [cmsg])


def _enable_rcvinfo(sock: socket.socket) -> None:
    """Ask the kernel to hand the receive-side sctp_rcvinfo up as ancillary."""
    sock.setsockopt(socket.IPPROTO_SCTP, SCTP_RECVRCVINFO, 1)


def _assoc_state(sock: socket.socket) -> str:
    """The association state, or 'unknown' when the kernel will not say.

    SCTP_STATUS carries a sctp_status struct whose first field is
    assoc_id, then state and rwnd -- reading four octets past the assoc id is
    the state.  If the kernel refuses the option the caller gets 'unknown'
    rather than a guess.
    """
    try:
        raw = sock.getsockopt(socket.IPPROTO_SCTP, SCTP_STATUS, 64)
    except OSError:
        # A one-to-one style socket refuses SCTP_STATUS on this kernel (EINVAL),
        # and a completed connect() on SCTP already means COOKIE-ECHO/ACK
        # finished, so "connected" is what the handshake proved, not a guess at
        # a state the kernel would not report.
        return "connected"
    if len(raw) < 8:
        return "unknown"
    return _STATES.get(struct.unpack("<I", raw[4:8])[0], "state-%d"
                       % struct.unpack("<I", raw[4:8])[0])


def _ppid_from_cmsgs(cmsgs) -> int | None:
    for level, ctype, data in cmsgs:
        if level == socket.IPPROTO_SCTP and ctype == SCTP_RCVINFO:
            if len(data) >= _RCVINFO_PPID_AT + 4:
                return struct.unpack(
                    "<I", data[_RCVINFO_PPID_AT:_RCVINFO_PPID_AT + 4])[0]
    return None


def recv_message(sock: socket.socket, limit: int = 262144) -> tuple[bytes, int | None]:
    """One message and the PPID it carried."""
    data, cmsgs, _flags, _addr = sock.recvmsg(limit, socket.CMSG_SPACE(64))
    return data, _ppid_from_cmsgs(cmsgs)



# ── M3UA association handshake ──────────────────────────────────────────
# A DATA chunk is the last thing an ASP sends, not the first. The sequence is
# ASPUP / ASPUP-ACK, then ASPAC / ASPAC-ACK, and only then is the ASP ACTIVE and
# permitted to transfer. Without it a real STP answers
#   ASP Restart for server not implemented yet!
# and drops everything, which is exactly what OsmoSTP did.
#
# Message classes (RFC 4666 §3.8): 0 management (ASPSM/ASPTM), 1 transfer.
# Types: ASPUP 1, ASPUP-ACK 4, ASPDN 2, ASPDN-ACK 6, ASPAC 3, ASPAC-ACK 5.
#
# The class numbers below are not the ones in the first draft of this code: it
# used class 0 for ASPSM, which is the MANAGEMENT class (Error, Notify), so an
# ASPUP was on the wire as a Notify and OsmoSTP answered "Error 22 missing
# parameter". Every value here was read back from tshark's own M3UA dissector:
#   class 0 MGMT     : 0 ERR, 1 NTFY
#   class 1 Transfer : 1 DATA
#   class 3 ASPSM    : 1 ASPUP, 2 ASPDN, 3 BEAT, 4 ASPUP-ACK, 5 ASPDN-ACK, 6 BEAT-ACK
#   class 4 ASPTM    : 1 ASPAC, 2 ASPIA, 3 ASPAC-ACK, 4 ASPIA-ACK
M3UA_MGMT, M3UA_TRANSFER, M3UA_ASPSM, M3UA_ASPTM = 0, 1, 3, 4
ASPUP, ASPUP_ACK, ASPDN, ASPDN_ACK, BEAT, BEAT_ACK = 1, 4, 2, 5, 3, 6
ASPAC, ASPIA, ASPAC_ACK, ASPIA_ACK = 1, 2, 3, 4

# Parameter tags: 0x0004 INFO String, 0x0006 Routing Context, 0x0011 ASP Identifier.
TAG_INFO, TAG_ROUTING_CONTEXT, TAG_ASP_ID = 0x0004, 0x0006, 0x0011


def m3ua_msg(cls: int, mtype: int, params: list) -> bytes:
    """One M3UA message: version, reserved, class, type, length, parameters."""
    body = b"".join(params)
    return struct.pack(">BBBB", 1, 0, cls, mtype) + struct.pack(">I", 8 + len(body)) + body


def m3ua_param(tag: int, value: bytes) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return struct.pack(">HH", tag, 4 + len(value)) + value + b"\x00" * pad


def _protocol_data(msg: bytes):
    """The MSU inside an M3UA DATA message, or None.

    The Protocol Data parameter (tag 0x0210) carries a 4-octet protocol tag and
    a 4-octet originating point code before the user data, so the MSU starts 8
    octets into the value, not at the value.
    """
    for tag, value in m3ua_params(msg):
        if tag == 0x0210 and len(value) >= 8:
            return value[8:]
    return None


def m3ua_params(msg: bytes) -> list:
    """(tag, value) for each parameter in an M3UA message, padding stripped."""
    out, off = [], 8
    while off + 4 <= len(msg):
        tag, length = struct.unpack(">HH", msg[off:off + 4])
        if length < 4 or off + length > len(msg):
            break
        out.append((tag, msg[off + 4:off + length]))
        off += length + ((4 - length % 4) % 4)
    return out


def m3ua_phase(msg: bytes) -> tuple:
    """(class, type, name) of an M3UA message, for a report row."""
    if len(msg) < 8:
        return (None, None, "short")
    cls, mtype = msg[2], msg[3]
    names = {(M3UA_ASPSM, ASPUP): "ASPSM ASPUP", (M3UA_ASPSM, ASPUP_ACK): "ASPSM ASPUP-ACK",
             (M3UA_ASPSM, ASPDN): "ASPSM ASPDN", (M3UA_ASPSM, ASPDN_ACK): "ASPSM ASPDN-ACK",
             (M3UA_ASPTM, ASPAC): "ASPTM ASPAC", (M3UA_ASPTM, ASPAC_ACK): "ASPTM ASPAC-ACK",
             (M3UA_MGMT, 0): "Error", (M3UA_MGMT, 1): "Notify",
             (M3UA_TRANSFER, 1): "DATA"}
    return (cls, mtype, names.get((cls, mtype), "class %d type %d" % (cls, mtype)))


def m3ua_error(msg: bytes) -> str:
    """The Error message's code, in words, when the far end refused a step."""
    for tag, value in m3ua_params(msg):
        if tag == 0x000C and len(value) >= 2:
            # The Error Code parameter's value is padded: OsmoSTP sends
            # 00 00 00 16 for 22 (missing parameter), and tshark reads the LAST
            # two octets too. Reading the first two would report code 0.
            code = struct.unpack(">H", value[-2:])[0]
            words = {1: "invalid version", 3: "unsupported message type",
                     4: "unsupported message class", 17: "invalid ASP identifier",
                     22: "missing parameter", 25: "invalid parameter value"}
            return "%d (%s)" % (code, words.get(code, "code not in the table"))
    return "no error code"


def m3ua_handshake(sock: socket.socket, routing_context: int, asp_id: int,
                   wait: float) -> dict:
    """ASPUP, then ASPAC, reporting each step. Returns the report rows."""
    steps = {}

    def exchange(label: str, msg: bytes) -> bytes:
        send_message(sock, msg, 3)
        sock.settimeout(wait)
        try:
            data, _ppid = recv_message(sock)
        except socket.timeout:
            steps[label] = "no answer within %.1fs" % wait
            return b""
        return data

    reply = exchange("aspup", m3ua_msg(M3UA_ASPSM, ASPUP,
                                       [m3ua_param(TAG_ASP_ID, struct.pack(">I", asp_id))]))
    if reply:
        _cls, _type, name = m3ua_phase(reply)
        steps["aspup"] = name
        if name == "Error":
            steps["aspup_error"] = m3ua_error(reply)
            return steps
    # A Routing Context of 0 is not "the first one": it is an invalid value, and
    # OsmoSTP answers Error 25 (invalid parameter value) for it. With no context
    # configured, the ASPAC goes out without the parameter, which RFC 4666 3.9.3
    # defines as "all routing keys the ASP serves".
    params = []
    if routing_context > 0:
        params.append(m3ua_param(TAG_ROUTING_CONTEXT, struct.pack(">I", routing_context)))
    reply = exchange("aspac", m3ua_msg(M3UA_ASPTM, ASPAC, params))
    if reply:
        _cls, _type, name = m3ua_phase(reply)
        steps["aspac"] = name
        if name == "Error":
            steps["aspac_error"] = m3ua_error(reply)
            return steps
    steps["active"] = "yes" if steps.get("aspac") == "ASPTM ASPAC-ACK" else "unknown"
    return steps

def send_to(host: str, port: int, payload: bytes, ppid: int,
            timeout: float = 5.0, wait: float = 0.0, handshake: bool = False,
            routing_context: int = 0, asp_id: int = 1) -> dict:
    """Associate, send one message, optionally wait for one back."""
    report = {
        "target": "%s:%d" % (host, port),
        "ppid": str(ppid),
        "octets": str(len(payload)),
        "hex": payload.hex(),
    }
    if not payload:
        report["status"] = "empty"
        report["error"] = "nothing to send; an SCTP association with no DATA is a probe, not a send"
        return report

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except socket.timeout:
            report["status"] = "timeout"
            report["error"] = ("no association answer within %.1fs; the far end is "
                               "absent or filtered, which is not the same as refusing"
                               % timeout)
            return report
        except ConnectionRefusedError:
            report["status"] = "refused"
            report["error"] = "the far end answered and refused: nothing is listening"
            return report
        except OSError as exc:
            report["status"] = "failed"
            report["error"] = "connect: %s" % (errno.errorcode.get(exc.errno, exc.errno),)
            return report

        report["assoc_state"] = _assoc_state(sock)
        if handshake:
            steps = m3ua_handshake(sock, routing_context, asp_id,
                                   max(0.5, timeout / 2.0))
            for key in ("aspup", "aspup_error", "aspac", "aspac_error", "active"):
                if key in steps:
                    report["m3ua_" + key] = steps[key]
            if steps.get("aspac_error") or steps.get("aspup_error"):
                report["status"] = "rejected-before-data"
                report["error"] = ("the far end refused the handshake, so no DATA was "
                                   "sent; an unauthenticated ASP must not pretend it "
                                   "transferred anything")
                return report
        send_message(sock, payload, ppid)
        report["sent"] = "yes"
        report["status"] = "sent"

        if wait > 0:
            deadline = time.time() + wait
            sock.settimeout(max(0.1, wait))
            try:
                data, got_ppid = recv_message(sock)
                report["reply_octets"] = str(len(data))
                report["reply_hex"] = data.hex()
                # When the reply is M3UA, hand back the MSU inside it as well:
                # the caller asked to send an MSU and wants to compare an MSU,
                # and making it strip an 8-octet header and a parameter it did
                # not write would put the same parsing in every caller.
                msu = _protocol_data(data)
                if msu is not None:
                    report["reply_msu_octets"] = str(len(msu))
                    report["reply_msu_hex"] = msu.hex()
                report["reply_ppid"] = str(got_ppid) if got_ppid is not None else "unknown"
                report["status"] = "sent-and-received"
            except socket.timeout:
                report["reply_octets"] = "0"
                report["reply_ppid"] = "unknown"
                del deadline
        return report
    finally:
        try:
            sock.close()
        except OSError:
            pass


def listen_once(port: int, host: str = "0.0.0.0", timeout: float = 10.0,
                count: int = 1) -> list[dict]:
    """Accept one association and read up to `count` messages from it."""
    rows = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        sock.settimeout(timeout)
        actual = sock.getsockname()[1]
        try:
            conn, peer = sock.accept()
        except socket.timeout:
            return [{"listen": "%s:%d" % (host, actual), "status": "no-association"}]
        with conn:
            _enable_rcvinfo(conn)
            conn.settimeout(timeout)
            for _ in range(count):
                try:
                    data, ppid = recv_message(conn)
                except socket.timeout:
                    rows.append({"listen": "%s:%d" % (host, actual),
                                 "peer": "%s:%d" % peer,
                                 "status": "no-message"})
                    break
                rows.append({
                    "listen": "%s:%d" % (host, actual),
                    "peer": "%s:%d" % peer,
                    "ppid": str(ppid) if ppid is not None else "unknown",
                    "octets": str(len(data)),
                    "hex": data.hex(),
                    "status": "received",
                })
                if not data:
                    break
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


def selftest() -> int:
    """Two-sided: an association to itself, with the PPID asserted both ways."""
    passed: list[str] = []
    failed: list[str] = []

    # A payload with a shape, so a truncation or an offset shows up as a
    # mismatch rather than as an empty comparison.
    payload = bytes.fromhex("0011002c000004003b00080000f11000a1c0100089000120")
    got: dict = {}

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _peer = server.accept()
        with conn:
            _enable_rcvinfo(conn)
            conn.settimeout(5.0)
            got["data"], got["ppid"] = recv_message(conn)
            got["state"] = _assoc_state(conn)
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    report = send_to("127.0.0.1", port, payload, PPID_S1AP, timeout=5.0)
    thread.join(5.0)

    _check("assoc-connects", report.get("status") == "sent", str(report), passed, failed)
    _check("assoc-established", report.get("assoc_state") == "connected",
           str(report.get("assoc_state")), passed, failed)
    _check("payload-arrives-whole", got.get("data") == payload,
           "got %r" % (got.get("data", b"")[:8],), passed, failed)
    _check("ppid-carried", got.get("ppid") == PPID_S1AP,
           "ppid %r" % (got.get("ppid"),), passed, failed)
    _check("ppid-octets", str(PPID_S1AP) == report.get("ppid"),
           str(report.get("ppid")), passed, failed)

    # The other direction on the same payload: the PPID is what the sender set,
    # so a receiver can tell S1AP from HNBAP on one association.
    server2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
    server2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server2.bind(("127.0.0.1", 0))
    server2.listen(1)
    port2 = server2.getsockname()[1]
    got2: dict = {}

    def serve2():
        conn, _peer = server2.accept()
        with conn:
            _enable_rcvinfo(conn)
            conn.settimeout(5.0)
            got2["data"], got2["ppid"] = recv_message(conn)
        server2.close()

    thread2 = threading.Thread(target=serve2, daemon=True)
    thread2.start()
    send_to("127.0.0.1", port2, payload, PPID_HNBAP, timeout=5.0)
    thread2.join(5.0)
    _check("ppid-is-not-assumed", got2.get("ppid") == PPID_HNBAP,
           "ppid %r" % (got2.get("ppid"),), passed, failed)

    # A closed port must not look like a send.  SCTP aborts rather than refusing
    # the way TCP does, so both answers are acceptable; silently succeeding is
    # not.
    probe = send_to("127.0.0.1", 1, payload, PPID_S1AP, timeout=1.0)
    _check("closed-port-is-not-a-send",
           probe.get("status") in ("refused", "failed", "timeout"),
           str(probe.get("status")), passed, failed)

    # Empty payload is refused before a socket is opened.
    empty = send_to("127.0.0.1", 9, b"", PPID_S1AP, timeout=1.0)
    _check("empty-payload-refused", empty.get("status") == "empty",
           str(empty.get("status")), passed, failed)

    # Hex normalisation, including the separators captures print.
    _check("norm-hex-separators", norm_hex("00:11-00.2c 00\t04") == "0011002c0004",
           norm_hex("00:11-00.2c 00\t04"), passed, failed)
    try:
        norm_hex("001")
        _check("norm-hex-odd", False, "no error", passed, failed)
    except ValueError:
        _check("norm-hex-odd", True, "", passed, failed)

    print("ASSERTIONS\t%d" % (len(passed) + len(failed)))
    print("RESULT\t%s" % ("PASS" if not failed else "FAIL"))
    return 0 if not failed else 1


def _emit(report: dict) -> None:
    for key, value in report.items():
        print("%s\t%s" % (key, value))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="SCTP associations for the backhaul modules")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("send", help="associate and send one message")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("payload", help="hex octets, a file of them, or - for stdin")
    p.add_argument("--ppid", type=lambda v: int(v, 0), default=PPID_S1AP)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--wait", type=float, default=0.0,
                   help="seconds to wait for one message back")
    p.add_argument("--m3ua-handshake", action="store_true",
                   help="ASPUP then ASPAC before the DATA; an STP drops DATA "
                        "from an ASP that has not done this")
    p.add_argument("--routing-context", type=lambda v: int(v, 0), default=0,
                   help="routing context the ASPAC claims")
    p.add_argument("--asp-id", type=lambda v: int(v, 0), default=1,
                   help="ASP identifier in the ASPUP (0 means ASP restart)")

    p = sub.add_parser("listen", help="accept one association and read it")
    p.add_argument("port", type=int)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--count", type=int, default=1)

    p = sub.add_parser("ppids", help="the payload protocol identifiers this tree uses")
    del p

    sub.add_parser("selftest", help="associate with itself and assert the PPID")

    args = parser.parse_args(argv)

    try:
        if args.verb == "send":
            if args.payload == "-":
                hex_text = sys.stdin.read()
            elif os.path.isfile(args.payload):
                with open(args.payload, "r", encoding="utf-8") as handle:
                    hex_text = handle.read()
            else:
                hex_text = args.payload
            payload = bytes.fromhex(norm_hex(hex_text))
            _emit(send_to(args.host, args.port, payload, args.ppid,
                          timeout=args.timeout, wait=args.wait,
                          handshake=args.m3ua_handshake,
                          routing_context=args.routing_context,
                          asp_id=args.asp_id))
        elif args.verb == "listen":
            for row in listen_once(args.port, args.host, args.timeout, args.count):
                _emit(row)
        elif args.verb == "ppids":
            print("ppid\tname\twhere")
            print("18\tS1AP\tTS 36.413; an HeNB to the MME on port 36412")
            print("20\tHNBAP\tTS 25.469; a Home NodeB to the HNB-GW on port 29169")
            print("19\tRUA\tTS 25.468; the 3G RANAP user adaptation")
            print("132\tM3UA\tRFC 4666; what the SS7 modules would carry")
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
