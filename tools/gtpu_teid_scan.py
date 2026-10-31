#!/usr/bin/env python3
"""Bounded TEID scan for modules/62_gtpu.sh -- build, plan, and (only then) send.

Every case is one GTP-U Echo Request whose only variable is the TEID:

    TS 29.281 5.1:  Version 1, PT 1, E/S/PN 0, message type 0x01 (Echo
                    Request), length 0 (no sequence number, no N-PDU when S and
                    PN are clear), then the four TEID octets.
    TS 29.281 7.2:  the receiver answers an Echo Request with an Echo Response.
                    An answer that carries the TEID we sent is an answer about
                    that TEID; anything else is an answer about the peer.

What the answers mean, and what they do not:

  answered:<type>  octets came back.  The type octet is printed so the operator
                   reads the peer's own word rather than this file's.
  unobserved       nothing came back inside the timeout.  This is NOT "the TEID
                   does not exist": the peer may be down, the path may filter
                   GTP-U, the answer may be rate limited, or the responder may
                   simply not echo.  Silence is grey, and grey is not clean.

The default is a dry run: it prints the exact octets it would put on the wire
and refuses to transmit without --transmit and a peer address.  The scan is
bounded by --max and paced by --rate; both are hard, so a typo in --end cannot
turn into a flood.

Exit 0 every case observed-or-planned, 1 no answer for at least one case (or a
refusal), 2 usage.
"""

import argparse
import socket
import struct
import sys
import time

GTPU_PORT = 2152
FLAGS = 0x32          # 5.1: version 1, PT 1, no extension, no sequence.
ECHO_REQUEST = 0x01
ECHO_RESPONSE = 0x02


def echo_request(teid):
    """The 8-octet Echo Request for one TEID (5.1 header, 7.2 message)."""
    return struct.pack("!BBHI", FLAGS, ECHO_REQUEST, 0, teid)


def probe(host, port, octets, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(octets, (host, port))
        data, peer = sock.recvfrom(2048)
        return data, peer
    except socket.timeout:
        return None, None
    except OSError as exc:
        return exc, None
    finally:
        sock.close()


def main(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("host", nargs="?")
    parser.add_argument("--start", default="0x00000001")
    parser.add_argument("--end", default="")
    parser.add_argument("--step", type=int, default=1)
    parser.add_argument("--max", type=int, default=64)
    parser.add_argument("--rate", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--port", type=int, default=GTPU_PORT)
    parser.add_argument("--plan-tsv", default="")
    parser.add_argument("--transmit", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if args.help:
        sys.stdout.write(__doc__)
        return 0
    if args.transmit and not args.host:
        sys.stderr.write("ERROR\t--transmit needs a peer address: this sends "
                         "only at a lab you own\n")
        return 2

    try:
        start = int(args.start, 0)
        end = int(args.end, 0) if args.end else start + (args.max - 1) * args.step
        step = max(1, args.step)
    except ValueError:
        sys.stderr.write("ERROR\t--start/--end/--step must be numbers\n")
        return 2
    if not 0 <= start <= 0xFFFFFFFF or not 0 <= end <= 0xFFFFFFFF:
        sys.stderr.write("ERROR\ta TEID is 32 bits (TS 29.281 5.1), so "
                         "0x00000000..0xFFFFFFFF\n")
        return 2
    if end < start:
        sys.stderr.write("ERROR\t--end is below --start\n")
        return 2

    wanted = (end - start) // step + 1
    if wanted > args.max:
        sys.stderr.write(
            "ERROR\tthe range covers %d TEIDs and --max is %d: raise --max "
            "deliberately, or narrow the range. A scan this module will not "
            "silently truncate is a scan whose count you chose.\n"
            % (wanted, args.max))
        return 1

    gap = 1.0 / args.rate if args.rate > 0 else 0.0
    rows = []
    failures = 0
    for index in range(wanted):
        teid = start + index * step
        octets = echo_request(teid)
        row = {"teid": "0x%08X" % (teid,), "octets": len(octets),
               "hex": octets.hex(), "verdict": "planned"}
        if args.transmit:
            data, peer = probe(args.host, args.port, octets, args.timeout)
            if isinstance(data, OSError):
                row["verdict"] = "send-error: %s" % (data.strerror or data,)
                failures += 1
            elif data is None:
                row["verdict"] = "unobserved"
                failures += 1
            else:
                kind = data[1] if len(data) > 1 else None
                row["verdict"] = ("answered:%02X" % kind) if kind is not None \
                    else "answered:empty"
            if gap:
                time.sleep(gap)
        rows.append(row)

    columns = ["teid", "octets", "hex", "verdict"]
    lines = ["\t".join(columns)]
    lines += ["\t".join(str(row[column]) for column in columns) for row in rows]
    if args.plan_tsv:
        with open(args.plan_tsv, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.write("cases\t%d\n" % (len(rows),))
    sys.stdout.write("mode\t%s\n" % ("transmitted" if args.transmit else "planned",))
    sys.stdout.write("first\t0x%08X\nlast\t0x%08X\nstep\t%d\n"
                     % (start, start + (wanted - 1) * step, step))
    if args.transmit:
        answered = sum(1 for row in rows if row["verdict"].startswith("answered"))
        sys.stdout.write("answered\t%d\nunobserved\t%d\n"
                         % (answered,
                            sum(1 for row in rows if row["verdict"] == "unobserved")))
        sys.stdout.write("note\tsilence is unobserved, not absent: a "
                         "non-answer does not prove the TEID is unused\n")
    else:
        sys.stdout.write("sent\tnothing: this run built %d packets and "
                         "printed them; --transmit is the only wire path\n"
                         % (len(rows),))
    return 0 if not args.transmit else (1 if failures else 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
