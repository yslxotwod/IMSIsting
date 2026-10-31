#!/usr/bin/env python3
"""The wire half of T1 (TEID-IP discovery) and of NBB delivery.

Why this is a separate file from ``grx_probe.py``
------------------------------------------------
``grx_probe.py`` answers "is anything there, and does it speak this protocol".
Its probe is stateless: an Echo Request to a fixed port, one question per
address.  T1 asks a different question, and the difference changes how silence
has to be read.

TS 29.281 §7.3 says a GTP-U entity that receives a G-PDU whose TEID it does not
know **may** discard it, and **may** answer with an Error Indication (type 26)
naming the offending TEID.  Both verbs are optional.  So:

    answered with type 26   the TEID is not in use   (definite)
    silence                 either the TEID is in use, OR this node never
                            implements the oracle, OR something dropped it

Silence alone therefore proves nothing, which is the whole reason this is not
just "ping with extra steps".  Two calibrations recover a reading:

  * A **path check** (an Echo Request to the same port) proves the port speaks
    GTP-U at all.  If the echo is silent, every TEID row is ``unobserved`` --
    not ``in-use`` -- because we never established that the peer answers
    anything.
  * An **oracle calibration**: if N independent TEIDs draw zero Error
    Indications, this node does not implement §7.3's optional answer.  Every
    silent TEID is then ``unobserved``, because the classification cannot be
    made.  A node with no oracle is enumerated by nothing, and reporting its
    whole range as "free" is the exact error this file exists to prevent.

Only when the echo answered *and* at least one probe drew an Error Indication
does silence mean in-use.  That is a state, not an inference, and it is printed
as one.

Safety
------
Every G-PDU this file sends carries a **zero-length payload**.  A guessed TEID
can collide with a live subscriber session (the space is 2^32 and a busy peer
holds hundreds of entries, so the odds are small but not zero).  A zero-length
G-PDU has no inner packet to decapsulate, so even a collision delivers nothing
a peer can forward.  The probe can therefore be run against a production node
without injecting traffic into anyone's session, and this is why the TEID
oracle is worth having at all: it reads the table without writing to it.

What this does not do
---------------------
It does not spoof a source address, walk a range, retransmit beyond ``--retries``
or attempt any authenticated message.  It sends G-PDUs with guessed TEIDs and
Echo Requests, and it reports what came back.

Output
------
Row-oriented TSV, no header (the caller writes it)::

    STATE  echo   <answered|silent|unreachable|send-error>  <rtt|->  <detail>
    STATE  oracle <present|absent|unknown>                  -        <detail>
    ROW    <teid-hex>  <verdict>  <rtt|->  <detail>

``verdict`` is one of ``error-indication``, ``in-use``, ``unobserved``,
``answered-other``.  ``in-use`` appears only when both calibrations passed.
"""

from __future__ import annotations

import argparse
import errno
import random
import socket
import struct
import sys
import time

# GTPv1-U Echo Request (TS 29.281 §7.2), in the shape peers actually answer.
#
# This is EIGHT octets: flags 0x32, type 1, length 4, TEID 0, and then nothing.
# A spec-literal builder adds the four optional octets (sequence, N-PDU,
# next-extension-type) that the Length of 4 promises, for twelve octets total --
# and that form is answered by NOTHING.  Measured on AS25144 109.165.152.1,
# interleaved three times each so rate limiting was ruled out:
#
#     8B  len4  no-opts   32020008000000000000000001c90e00   answered, 3/3
#     8B  len0            -- timeout --
#     12B len4 S=1        -- timeout --
#     12B len4 E=1        -- timeout --
#
# The peer answers only this one shape.  A probe that sends the well-formed
# variant and reports "no answer" has measured its own framing error, not the
# network -- which is exactly the trap the path check exists to avoid, so the
# path check uses the shape already proven against the population.
GTPU_ECHO = bytes.fromhex("3201000400000000")

GTPU_GPDU = 0xFF
GTPU_ECHO_REQ = 0x01
GTPU_ECHO_RSP = 0x02
GTPU_ERROR_INDICATION = 0x1A
GTPU_END_MARKER = 0xFE

# IE type for TEID-I (TS 29.281 §7.3.1): the responder names the TEID it could
# not resolve.  Present in every well-formed Error Indication.
IE_TEID_I = 16


def gpdu(teid: int) -> bytes:
    """A G-PDU with a guessed TEID and a ZERO-LENGTH payload.

    Zero length is deliberate and load-bearing: on a TEID collision there is no
    inner packet, so nothing is delivered to anyone's session.  See the module
    docstring.
    """
    return bytes([0x30, GTPU_GPDU, 0x00, 0x00]) + struct.pack(">I", teid)


def _read_ies(data: bytes, off: int) -> list[tuple[int, bytes]]:
    """IEs from the group-message tail: type(1) length(2) value.

    A malformed tail stops the walk rather than raising: a peer that answers
    with a truncated Error Indication still told us what we needed (that it
    answers), and the shape of the remainder is not our finding.
    """
    out: list[tuple[int, bytes]] = []
    while off + 3 <= len(data):
        itype = data[off]
        ilen = int.from_bytes(data[off + 1:off + 3], "big")
        if off + 3 + ilen > len(data):
            break
        out.append((itype, data[off + 3:off + 3 + ilen]))
        off += 3 + ilen
        if itype == 0:  # no more IEs
            break
    return out


def parse_reply(data: bytes, want_teid: int) -> tuple[str, str]:
    """Classify a datagram that arrived in answer to a G-PDU probe.

    Returns ``(verdict, detail)``.  A datagram that is not GTP-U at all is
    reported as ``answered-other`` with its length, never folded into silence:
    something answered, and what answered is a different fact from nothing
    having answered.
    """
    if len(data) < 8:
        return ("answered-other", "short-%d-octets" % len(data))
    flags = data[0]
    version = (flags >> 5) & 0x07
    if version != 1:
        return ("answered-other", "not-gtpu-v%d" % version)
    mtype = data[1]
    if mtype == GTPU_ERROR_INDICATION:
        # The TEID field of an Error Indication is 0; the offending TEID lives
        # in the IEs.  Confirm it names ours where the peer bothered to say.
        #
        # TS 29.281 §5.1: the four optional octets (sequence 2, N-PDU 1,
        # next-extension-type 1) are present when ANY of E, S or PN is set, and
        # Length counts them.  The IEs start after those, not after the fixed
        # header -- reading from octet 8 shifts every IE by four and makes a
        # well-formed answer look like it named no TEID at all.
        e = bool(flags & 0x04)
        s = bool(flags & 0x02)
        pn = bool(flags & 0x01)
        off = 12 if (e or s or pn) else 8
        length = int.from_bytes(data[2:4], "big")
        body = data[off:8 + length] if length else data[off:]
        named = None
        for itype, ival in _read_ies(body, 0):
            if itype == IE_TEID_I and len(ival) >= 4:
                named = int.from_bytes(ival[:4], "big")
                break
        if named is None:
            return ("error-indication", "names-teid-unstated")
        if named == want_teid:
            return ("error-indication", "names-teid-confirmed")
        return ("error-indication", "names-teid-other-%08X" % named)
    if mtype == GTPU_ECHO_RSP:
        return ("answered-other", "echo-response")
    if mtype == GTPU_END_MARKER:
        return ("answered-other", "end-marker")
    return ("answered-other", "type-%d" % mtype)


def send(sock: socket.socket, payload: bytes, addr: tuple[str, int],
         timeout: float) -> tuple[str, float | None, bytes | None, str]:
    """One datagram out, at most one in.  Returns (outcome, rtt_ms, data, detail)."""
    start = time.monotonic()
    try:
        sock.sendto(payload, addr)
    except OSError as exc:
        return ("send-error", None, None, errno.errorcode.get(exc.errno, "e-send"))
    try:
        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        return ("silent", None, None, "no-reply")
    except ConnectionRefusedError:
        # ICMP port unreachable: the host's stack answered. Not the same fact
        # as silence, and never reported as it.
        return ("unreachable", None, None, "icmp-port-unreachable")
    except OSError as exc:
        return ("send-error", None, None, errno.errorcode.get(exc.errno, "e-recv"))
    return ("answered", (time.monotonic() - start) * 1000.0, data, "")


def echo_state(sock: socket.socket, addr: tuple[str, int],
               timeout: float, retries: int) -> tuple[str, float | None, str]:
    """Does this port answer a GTP-U Echo at all?

    This is the path check that makes silence interpretable.  Retried, because a
    single lost datagram on a lossy path must not be reported as a dead port.
    """
    last = ("silent", None, "no-reply")
    for _ in range(max(1, retries)):
        outcome, rtt, data, detail = send(sock, GTPU_ECHO, addr, timeout)
        if outcome != "answered":
            last = (outcome, None, detail)
            continue
        if len(data) >= 2 and ((data[0] >> 5) & 0x07) == 1 and data[1] == GTPU_ECHO_RSP:
            return ("answered", rtt, "echo-response")
        if len(data) >= 2 and data[1] == GTPU_ERROR_INDICATION:
            return ("answered", rtt, "error-indication")
        return ("answered", rtt, "answered-not-echo")
    return last


class Bucket:
    """Token bucket, no bursts.  A peer that rate-limits us turns our own
    sending rate into what looks like absence, which is the failure this
    campaign already paid for once."""

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


def teid_list(args: argparse.Namespace) -> list[int]:
    """The TEIDs to try, in order, deduplicated."""
    out: list[int] = []
    if args.teid:
        out.append(int(args.teid, 16))
    if args.t_from or args.t_to:
        lo = int(args.t_from or "0", 16)
        hi = int(args.t_to or args.t_from or "0", 16)
        if hi < lo:
            lo, hi = hi, lo
        out.extend(range(lo, hi + 1))
    if args.count:
        rng = random.Random(args.seed)
        out.extend(rng.getrandbits(32) for _ in range(args.count))
    seen: set[int] = set()
    uniq: list[int] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(add_help=True, description="GTP-U TEID probe (T1)")
    p.add_argument("host", help="peer address")
    p.add_argument("--port", type=int, default=2152)
    p.add_argument("--teid", default="", help="one TEID, hex")
    p.add_argument("--from", dest="t_from", default="", help="first TEID of a range, hex")
    p.add_argument("--to", dest="t_to", default="", help="last TEID of a range, hex")
    p.add_argument("--count", type=int, default=0, help="this many random TEIDs")
    p.add_argument("--seed", type=int, default=0, help="seed for --count")
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--rate", type=float, default=8.0, help="probes per second")
    p.add_argument("--no-echo", action="store_true", help="skip the path check")
    args = p.parse_args(argv)

    teids = teid_list(args)
    if not teids:
        print("ERROR\tgive --teid, --from/--to or --count", file=sys.stderr)
        return 2
    if len(teids) > 4096:
        print("ERROR\t%d TEIDs is more than one run should send; split it" % len(teids),
              file=sys.stderr)
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
        # ── calibration 1: does the port speak GTP-U at all? ─────────────
        if args.no_echo:
            est, ertt, edet = ("skipped", None, "path-check-not-requested")
        else:
            est, ertt, edet = echo_state(sock, addr, args.timeout, args.retries)
        print("STATE\techo\t%s\t%s\t%s" % (
            est, "-" if ertt is None else "%.1f" % ertt, edet))
        sys.stdout.flush()

        path_ok = est == "answered"

        # ── probe ────────────────────────────────────────────────────────
        rows: list[tuple[int, str, float | None, str]] = []
        ei_count = 0
        for teid in teids:
            bucket.take()
            verdict, rtt, detail = "unobserved", None, "no-reply"
            for _ in range(max(1, args.retries)):
                outcome, rtt, data, sdetail = send(sock, gpdu(teid), addr, args.timeout)
                if outcome == "answered" and data is not None:
                    verdict, detail = parse_reply(data, teid)
                    break
                verdict, detail = "unobserved", sdetail
                if outcome == "unreachable":
                    break
            if verdict == "error-indication":
                ei_count += 1
            rows.append((teid, verdict, rtt, detail))

        # ── calibration 2: does this node implement the §7.3 oracle? ─────
        # Zero Error Indications across the whole run means silence carries no
        # information here: either the answer is not implemented or everything
        # was filtered.  Either way `in-use` would be a fabrication.
        if ei_count > 0:
            oracle, odet = "present", "%d-of-%d-answered" % (ei_count, len(rows))
        elif not path_ok:
            oracle, odet = "unknown", "path-check-did-not-answer"
        else:
            oracle, odet = "absent", "no-error-indication-in-%d-probes" % len(rows)
        print("STATE\toracle\t%s\t-\t%s" % (oracle, odet))
        sys.stdout.flush()

        for teid, verdict, rtt, detail in rows:
            # The only place silence becomes a positive claim, and only here.
            if verdict == "unobserved" and detail == "no-reply" and path_ok and oracle == "present":
                verdict = "in-use"
            print("ROW\t%08X\t%s\t%s\t%s" % (
                teid, verdict, "-" if rtt is None else "%.1f" % rtt, detail))
            sys.stdout.flush()

        # ── calibration 1 again: was the path still up when we finished? ──
        if not args.no_echo:
            post, prtt, pdet = echo_state(sock, addr, args.timeout, 1)
            print("STATE\tpost_echo\t%s\t%s\t%s" % (
                post, "-" if prtt is None else "%.1f" % prtt, pdet))
            sys.stdout.flush()
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
