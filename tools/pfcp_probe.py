#!/usr/bin/env python3
"""The wire half of T2: SEID enumeration over PFCP (UDP 8805).

Why an empty message is the oracle
----------------------------------
TS 29.244 says a Session Modification Request carries a SEID in its header and
then the IEs that say *what* to modify.  It does not say what a node must do with
a request that names a SEID but updates nothing -- a gap, not an oversight, in
the same family as the "may" in TS 29.281 §7.3 that T1 rides.

Real stacks split on it:

    Session context not found (64)   the SEID is not this node's
    anything else                    the SEID resolved, and the request was read

So the cause, not the echoed SEID, is the answer.  A response header carries a
SEID whether or not the session exists, which is why reading it tells you
nothing: it is the Cause IE (19) that distinguishes.

An empty request is also *inert*.  With no PDR, FAR, QER or URR in the body
there is nothing to install, update or remove, so a node that accepts it has
changed no forwarding state.  That is what makes the oracle worth having: it
reads the session table without writing to it.

Two calibrations, for the same reason as ``gtpu_probe.py``
----------------------------------------------------------
A Heartbeat (type 1) to the same port proves the node speaks PFCP at all.  If it
does not answer, no SEID row is a claim about a SEID.

And a node that answers *every* guess with the same non-64 cause is not
discriminating at all -- it is echoing a policy error.  Reporting those as
"exists" would invent a session table out of a rejection.  So the run tracks
whether any cause-64 was seen: without one, the verdict every row gets is
``unobserved``, and the summary says the oracle is degenerate.

Output
------
Row-oriented TSV, no header (the caller writes it)::

    STATE  heartbeat  <answered|silent|unreachable|send-error>  <rtt|->  <detail>
    STATE  oracle     <present|degenerate|unknown>              -        <detail>
    ROW    <seid-hex> <verdict>  <rtt|->  <cause>  <detail>

``verdict`` is ``absent``, ``exists``, ``unobserved`` or ``answered-other``.
"""

from __future__ import annotations

import argparse
import errno
import random
import socket
import sys
import time

# PFCP header (TS 29.244 §5.2): flags(1) type(1) length(2) then, when S=1, an
# 8-octet SEID, then sequence(3) and spare(1).  Length counts everything after
# the first four octets.

PFCP_HEARTBEAT_REQ = 1
PFCP_HEARTBEAT_RSP = 2
PFCP_SESSION_MOD_REQ = 52
PFCP_SESSION_MOD_RSP = 53
PFCP_SESSION_EST_RSP = 51

IE_CAUSE = 19

# TS 29.244 Table 8.2.1-1, the rows this file names.
CAUSE_NAMES = {
    1: "request-accepted",
    2: "more-usage-report",
    3: "request-partially-accepted",
    64: "session-context-not-found",
    65: "mandatory-ie-missing",
    66: "conditional-ie-missing",
    67: "invalid-length",
    68: "mandatory-ie-incorrect",
    69: "invalid-forwarding-policy",
    70: "invalid-f-teid-allocation-option",
    71: "no-established-pfcp-association",
    72: "rule-creation-modification-failure",
    73: "pfcp-entity-in-congestion",
    74: "no-resources-available",
    75: "service-not-supported",
    76: "system-failure",
}


def heartbeat(seq: int = 1) -> bytes:
    """Heartbeat Request: S=0, no SEID, no IEs.  TS 29.244 §7.1."""
    return bytes([0x20, PFCP_HEARTBEAT_REQ, 0x00, 0x04]) + \
        seq.to_bytes(3, "big") + b"\x00"


def session_mod_empty(seid: int, seq: int = 1) -> bytes:
    """A Session Modification Request that names a SEID and updates nothing.

    Length is 8 (SEID) + 4 (sequence + spare) with an empty body.  Inert by
    construction -- see the module docstring.
    """
    body = b""
    length = 8 + 4 + len(body)
    return bytes([0x21, PFCP_SESSION_MOD_REQ]) + length.to_bytes(2, "big") + \
        (seid & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big") + \
        seq.to_bytes(3, "big") + b"\x00" + body


def _ies(data: bytes, off: int) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    while off + 4 <= len(data):
        itype = int.from_bytes(data[off:off + 2], "big")
        ilen = int.from_bytes(data[off + 2:off + 4], "big")
        if off + 4 + ilen > len(data):
            break
        out.append((itype, data[off + 4:off + 4 + ilen]))
        off += 4 + ilen
    return out


def parse(data: bytes) -> tuple[int, int, int | None, int]:
    """(message type, cause or None, cause-text, seid) from a PFCP datagram.

    ``seid`` is the header SEID when S=1, else 0; it is returned so the caller can
    show that the response echoes a SEID regardless of whether the session
    exists -- which is why the cause, not this, decides the verdict.
    """
    if len(data) < 8:
        return (-1, None, 0)
    mtype = data[1]
    flags = data[0]
    s = flags & 0x01
    off = 4
    seid = 0
    if s:
        if len(data) < 12:
            return (-1, None, 0)
        seid = int.from_bytes(data[4:12], "big")
        off = 12
    off += 4  # sequence(3) + spare(1)
    cause = None
    for itype, ival in _ies(data, off):
        if itype == IE_CAUSE and len(ival) >= 1:
            cause = ival[0]
            break
    return (mtype, cause, seid)


def send(sock: socket.socket, payload: bytes, addr: tuple[str, int],
         timeout: float) -> tuple[str, float | None, bytes | None, str]:
    start = time.monotonic()
    try:
        sock.sendto(payload, addr)
    except OSError as exc:
        return ("send-error", None, None, errno.errorcode.get(exc.errno, "e-send"))
    try:
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return ("silent", None, None, "no-reply")
    except ConnectionRefusedError:
        return ("unreachable", None, None, "icmp-port-unreachable")
    except OSError as exc:
        return ("send-error", None, None, errno.errorcode.get(exc.errno, "e-recv"))
    return ("answered", (time.monotonic() - start) * 1000.0, data, "")


def heartbeat_state(sock: socket.socket, addr: tuple[str, int],
                    timeout: float, retries: int) -> tuple[str, float | None, str]:
    last = ("silent", None, "no-reply")
    for _ in range(max(1, retries)):
        outcome, rtt, data, detail = send(sock, heartbeat(), addr, timeout)
        if outcome != "answered":
            last = (outcome, None, detail)
            continue
        mtype, cause, _ = parse(data)
        if mtype == PFCP_HEARTBEAT_RSP:
            return ("answered", rtt, "heartbeat-response")
        if mtype == -1:
            return ("answered", rtt, "not-pfcp-%d-octets" % len(data))
        return ("answered", rtt, "type-%d" % mtype)
    return last


class Bucket:
    def __init__(self, rate: float) -> None:
        self.rate = max(0.1, rate)
        self.tokens = 1.0
        self.last = time.monotonic()

    def take(self) -> None:
        now = time.monotonic()
        self.tokens = min(1.0, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens < 1.0:
            time.sleep((1.0 - self.tokens) / self.rate)
            self.tokens = 0.0
            self.last = time.monotonic()
        else:
            self.tokens -= 1.0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(add_help=True, description="PFCP SEID enumeration (T2)")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=8805)
    p.add_argument("--seid", default="", help="one SEID as hex")
    p.add_argument("--from", dest="s_from", default="", help="first SEID, hex")
    p.add_argument("--to", dest="s_to", default="", help="last SEID, hex")
    p.add_argument("--count", type=int, default=0, help="this many random SEIDs")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--rate", type=float, default=8.0)
    p.add_argument("--no-heartbeat", action="store_true")
    args = p.parse_args(argv)

    seids: list[int] = []
    if args.seid:
        seids.append(int(args.seid, 16))
    if args.s_from or args.s_to:
        lo = int(args.s_from or "0", 16)
        hi = int(args.s_to or args.s_from or "0", 16)
        if hi < lo:
            lo, hi = hi, lo
        seids.extend(range(lo, hi + 1))
    if args.count:
        rng = random.Random(args.seed)
        seids.extend(rng.getrandbits(64) for _ in range(args.count))
    if not seids:
        print("ERROR\tgive --seid, --from/--to or --count", file=sys.stderr)
        return 2
    if len(seids) > 4096:
        print("ERROR\t%d SEIDs is more than one run should send; split it" % len(seids),
              file=sys.stderr)
        return 2
    # A SEID of 0 is the "no session" sentinel; probing it measures nothing.
    seids = [s for s in dict.fromkeys(seids) if s != 0]
    if not seids:
        print("ERROR\tevery SEID given was 0, which names no session", file=sys.stderr)
        return 2

    try:
        addr = (socket.gethostbyname(args.host), args.port)
    except OSError as exc:
        print("ERROR\tcannot resolve %s: %s" % (args.host, exc.strerror), file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    bucket = Bucket(args.rate)
    try:
        if args.no_heartbeat:
            hst, hrtt, hdet = ("skipped", None, "path-check-not-requested")
        else:
            hst, hrtt, hdet = heartbeat_state(sock, addr, args.timeout, args.retries)
        print("STATE\theartbeat\t%s\t%s\t%s" % (
            hst, "-" if hrtt is None else "%.1f" % hrtt, hdet))
        sys.stdout.flush()
        path_ok = hst == "answered"

        rows: list[tuple[int, str, float | None, str, int | None]] = []
        seen_cause_64 = False
        answered = 0
        for seid in seids:
            bucket.take()
            verdict, rtt, cause, detail = "unobserved", None, None, "no-reply"
            for _ in range(max(1, args.retries)):
                outcome, rtt, data, sdetail = send(
                    sock, session_mod_empty(seid), addr, args.timeout)
                if outcome == "answered" and data is not None:
                    answered += 1
                    mtype, cause, _hdr_seid = parse(data)
                    if mtype < 0:
                        verdict, detail = "answered-other", "not-pfcp-%d-octets" % len(data)
                    elif mtype != PFCP_SESSION_MOD_RSP:
                        verdict = "answered-other"
                        detail = "type-%d" % mtype
                    elif cause is None:
                        verdict, detail = "answered-other", "response-carries-no-cause"
                    elif cause == 64:
                        seen_cause_64 = True
                        verdict = "absent"
                        detail = CAUSE_NAMES.get(cause, "cause-%d" % cause)
                    else:
                        verdict = "exists"
                        detail = CAUSE_NAMES.get(cause, "cause-%d" % cause)
                    break
                verdict, detail = "unobserved", sdetail
                if outcome == "unreachable":
                    break
            rows.append((seid, verdict, rtt, detail, cause))

        # The oracle is only an oracle if it distinguishes. Answers that never
        # name 64 mean the node is rejecting on policy, not resolving a SEID.
        if not path_ok:
            oracle, odet = "unknown", "heartbeat-did-not-answer"
        elif seen_cause_64:
            oracle, odet = "present", "cause-64-observed-in-%d-probes" % len(rows)
        elif answered:
            oracle, odet = "degenerate", "%d-answers-no-cause-64" % answered
        else:
            oracle, odet = "unknown", "no-answer-at-all"
        print("STATE\toracle\t%s\t-\t%s" % (oracle, odet))
        sys.stdout.flush()

        for seid, verdict, rtt, detail, cause in rows:
            # `exists` from a node that never discriminates is not a finding.
            if verdict == "exists" and oracle != "present":
                verdict, detail = "unobserved", "cause-not-discriminating:" + detail
            if verdict == "absent" and oracle != "present":
                verdict, detail = "unobserved", "cause-not-discriminating:" + detail
            print("ROW\t%016X\t%s\t%s\t%s\t%s" % (
                seid, verdict, "-" if rtt is None else "%.1f" % rtt,
                "-" if cause is None else str(cause), detail))
            sys.stdout.flush()

        if not args.no_heartbeat:
            post, prtt, pdet = heartbeat_state(sock, addr, args.timeout, 1)
            print("STATE\tpost_heartbeat\t%s\t%s\t%s" % (
                post, "-" if prtt is None else "%.1f" % prtt, pdet))
            sys.stdout.flush()
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
